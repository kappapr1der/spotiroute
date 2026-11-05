using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

// Only the public, unauthenticated ClientHello and signed AP challenge are used.
// Protocol reference: librespot 99b6088bf3ea028f90192676ac1a337fa4b2ed12.
namespace SpotiRoute.Diagnostics {
    public sealed class AccessPointResult {
        public string Server;
        public int Port;
        public string RemoteAddress;
        public bool TcpConnected;
        public bool HelloSent;
        public bool ResponseReceived;
        public bool ServerSignatureVerified;
        public bool AuthenticationAttempted = false;
        public string Stage = "not_started";
        public string Error;
        public int ResponseBytes;
        public long Milliseconds;
    }
    public static class AccessPointProbe {
        const int MaxPacket = 65536;
        const string ServerModulus = "ace0460bffc230aff46bfec3bfbf863da191c6cc336c93a14fb3b01612acac6af180e7f614d9429dbe2e346643e362d2327a1a0d923baedd1402b18155056104d52c96a44c1ecc024ad4b20c001f17edc22fc43521c8f0cbaed2add72b0f9db3c5321a2afe59f35a0dac68f1fa621efb2c8d0cb7392d9247e3d7351a6dbd24c2ae255b88ffab73298a0bcccd0c58673189e8bd3480784a5fc96b899d956bfc86d74f33a6781796c9c32d0d32a5abcd0527e2f710a39613c42f99c027bfed049c3c275804b6b219f9c12f02e94863eca1b642a09d4825f8b39dd0e86af9484da1c2ba863042ea9db3086c190e48b39d66eb0006a25aeea11b13873cd719e655bd";
        const string DhPrime = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff";
        sealed class Field { public ulong Number; public int Wire; public ulong Value; public byte[] Bytes; }
        static byte[] Hex(string value) {
            byte[] bytes = new byte[value.Length / 2];
            for (int i=0; i<bytes.Length; i++) bytes[i]=Convert.ToByte(value.Substring(i*2,2),16);
            return bytes;
        }
        static BigInteger FromBigEndian(byte[] bytes) {
            byte[] little = new byte[bytes.Length+1];
            for (int i=0;i<bytes.Length;i++) little[i]=bytes[bytes.Length-1-i];
            return new BigInteger(little);
        }
        static byte[] ToBigEndian(BigInteger value) {
            byte[] little=value.ToByteArray(); int length=little.Length;
            while(length>1 && little[length-1]==0) length--;
            byte[] bytes=new byte[length];
            for(int i=0;i<length;i++) bytes[i]=little[length-1-i];
            return bytes;
        }
        static void Varint(Stream stream, ulong value) {
            while(value>=128){stream.WriteByte((byte)((value&127)|128));value>>=7;}
            stream.WriteByte((byte)value);
        }
        static void Integer(Stream stream,int field,ulong value) {
            Varint(stream,(ulong)field<<3);Varint(stream,value);
        }
        static void Bytes(Stream stream,int field,byte[] value) {
            Varint(stream,((ulong)field<<3)|2);Varint(stream,(ulong)value.Length);stream.Write(value,0,value.Length);
        }
        static byte[] Message(Action<Stream> write) {
            using(var stream=new MemoryStream()){write(stream);return stream.ToArray();}
        }
        static byte[] Hello() {
            byte[] random=new byte[95],nonce=new byte[16];
            using(var rng=RandomNumberGenerator.Create()){rng.GetBytes(random);rng.GetBytes(nonce);}
            byte[] publicKey=ToBigEndian(BigInteger.ModPow(new BigInteger(2),FromBigEndian(random),FromBigEndian(Hex(DhPrime))));
            byte[] build=Message(delegate(Stream s){Integer(s,10,0);Integer(s,20,0);Integer(s,30,Environment.Is64BitOperatingSystem?39UL:0UL);Integer(s,40,124200290);});
            byte[] dh=Message(delegate(Stream s){Bytes(s,10,publicKey);Integer(s,20,1);});
            byte[] crypto=Message(delegate(Stream s){Bytes(s,10,dh);});
            byte[] body=Message(delegate(Stream s){Bytes(s,10,build);Integer(s,30,0);Bytes(s,50,crypto);Bytes(s,60,nonce);Bytes(s,70,new byte[]{30});});
            uint length=(uint)(body.Length+6);
            byte[] framed=new byte[length];framed[0]=0;framed[1]=4;
            framed[2]=(byte)(length>>24);framed[3]=(byte)(length>>16);framed[4]=(byte)(length>>8);framed[5]=(byte)length;
            Buffer.BlockCopy(body,0,framed,6,body.Length);return framed;
        }
        static ulong ReadVarint(byte[] bytes,ref int offset) {
            ulong result=0;
            for(int shift=0;shift<70;shift+=7) {
                if(offset>=bytes.Length)throw new InvalidDataException("truncated_varint");
                byte b=bytes[offset++];
                if(shift==63 && b>1)throw new InvalidDataException("overflow_varint");
                result|=(ulong)(b&127)<<shift;
                if((b&128)==0)return result;
            }
            throw new InvalidDataException("overflow_varint");
        }
        static List<Field> Parse(byte[] bytes) {
            if(bytes.Length>MaxPacket)throw new InvalidDataException("oversized_message");
            var fields=new List<Field>();int offset=0;
            while(offset<bytes.Length) {
                if(fields.Count>=512)throw new InvalidDataException("too_many_fields");
                ulong key=ReadVarint(bytes,ref offset);
                if((key>>3)==0 || (key>>3)>536870911)throw new InvalidDataException("invalid_field_number");
                var field=new Field{Number=key>>3,Wire=(int)(key&7)};
                if(field.Wire==0)field.Value=ReadVarint(bytes,ref offset);
                else {
                    ulong length;
                    if(field.Wire==2)length=ReadVarint(bytes,ref offset);
                    else if(field.Wire==1)length=8;
                    else if(field.Wire==5)length=4;
                    else throw new InvalidDataException("unsupported_wire_type");
                    if(length>(ulong)(bytes.Length-offset))throw new InvalidDataException("truncated_field");
                    field.Bytes=new byte[(int)length];Buffer.BlockCopy(bytes,offset,field.Bytes,0,(int)length);offset+=(int)length;
                }
                fields.Add(field);
            }
            return fields;
        }
        static byte[] RequiredBytes(List<Field> fields,ulong number) {
            Field match=null;
            foreach(var field in fields)if(field.Number==number){if(match!=null || field.Wire!=2)throw new InvalidDataException("ambiguous_field");match=field;}
            if(match==null)throw new InvalidDataException("missing_field");
            return match.Bytes;
        }
        static void VerifyResponse(byte[] bytes,byte[] modulus) {
            var root=Parse(bytes);
            foreach(var field in root) {
                if(field.Number==20)throw new InvalidDataException("upgrade_response_unverified");
                if(field.Number==30)throw new InvalidDataException("rejection_response_unverified");
            }
            byte[] challenge=RequiredBytes(root,10);
            byte[] crypto=RequiredBytes(Parse(challenge),10);
            var dh=Parse(RequiredBytes(Parse(crypto),10));
            byte[] remote=RequiredBytes(dh,10),signature=RequiredBytes(dh,30);
            if(remote.Length<1 || remote.Length>96 || signature.Length!=256)throw new InvalidDataException("invalid_challenge_lengths");
            BigInteger remoteNumber=FromBigEndian(remote),prime=FromBigEndian(Hex(DhPrime));
            if(remoteNumber<=BigInteger.One || remoteNumber>=prime-BigInteger.One)throw new InvalidDataException("invalid_dh_value");
            using(var rsa=RSA.Create()){
                rsa.ImportParameters(new RSAParameters{Modulus=modulus,Exponent=new byte[]{1,0,1}});
                if(!rsa.VerifyData(remote,signature,HashAlgorithmName.SHA1,RSASignaturePadding.Pkcs1))throw new InvalidDataException("signature_verification_failed");
            }
        }
        static int Remaining(Stopwatch watch,int budget) {
            int remaining=budget-(int)watch.ElapsedMilliseconds;
            if(remaining<=0)throw new TimeoutException();
            return remaining;
        }
        static byte[] ReadExact(NetworkStream stream,int size,Stopwatch watch,int budget) {
            if(size<0 || size>MaxPacket)throw new InvalidDataException("invalid_packet_size");
            byte[] bytes=new byte[size];int offset=0;
            while(offset<size){
                stream.ReadTimeout=Remaining(watch,budget);
                int count=stream.Read(bytes,offset,size-offset);
                if(count==0)throw new EndOfStreamException();
                offset+=count;
            }
            return bytes;
        }
        static int BodySize(byte[] prefix) {
            uint length=((uint)prefix[0]<<24)|((uint)prefix[1]<<16)|((uint)prefix[2]<<8)|prefix[3];
            if(length<4 || length>MaxPacket)throw new InvalidDataException("invalid_packet_size");
            return (int)length-4;
        }
        static bool IsPublic(IPAddress address) {
            if(address.AddressFamily!=AddressFamily.InterNetwork)return false;
            byte[] b=address.GetAddressBytes();
            return !(b[0]==0 || b[0]==10 || b[0]==127 || b[0]>=224 || (b[0]==100 && b[1]>=64 && b[1]<=127) ||
                (b[0]==169 && b[1]==254) || (b[0]==172 && b[1]>=16 && b[1]<=31) ||
                (b[0]==192 && (b[1]==168 || (b[1]==0 && (b[2]==0 || b[2]==2)))) ||
                (b[0]==198 && (b[1]==18 || b[1]==19 || (b[1]==51 && b[2]==100))) ||
                (b[0]==203 && b[1]==0 && b[2]==113));
        }
        public static AccessPointResult Probe(string server,int port,int timeoutMilliseconds) {
            if(!Regex.IsMatch(server,@"\A[a-z0-9-]+\.(?:ap\.)?spotify\.com\z") || (port!=443 && port!=4070 && port!=80))throw new ArgumentException("Spotify AP target required");
            if(timeoutMilliseconds<500 || timeoutMilliseconds>15000)throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            var result=new AccessPointResult{Server=server,Port=port};
            var watch=Stopwatch.StartNew();
            using(var client=new TcpClient(AddressFamily.InterNetwork)){
                try {
                    result.Stage="dns";
                    var dns=Dns.GetHostAddressesAsync(server);
                    if(!dns.Wait(Math.Min(2500,Remaining(watch,timeoutMilliseconds))))throw new TimeoutException();
                    IPAddress selected=null;
                    foreach(var address in dns.Result)if(IsPublic(address)){selected=address;break;}
                    if(selected==null)throw new InvalidDataException("no_public_ipv4_address");
                    result.RemoteAddress=selected.ToString();result.Stage="tcp_connect";
                    var pending=client.BeginConnect(selected,port,null,null);
                    try{if(!pending.AsyncWaitHandle.WaitOne(Math.Min(3000,Remaining(watch,timeoutMilliseconds))))throw new TimeoutException();client.EndConnect(pending);}
                    finally{pending.AsyncWaitHandle.Close();}
                    result.TcpConnected=true;
                    using(var stream=client.GetStream()){
                        result.Stage="client_hello";
                        byte[] hello=Hello();stream.WriteTimeout=Remaining(watch,timeoutMilliseconds);stream.Write(hello,0,hello.Length);result.HelloSent=true;
                        result.Stage="server_response";
                        byte[] prefix=ReadExact(stream,4,watch,timeoutMilliseconds);
                        byte[] response=ReadExact(stream,BodySize(prefix),watch,timeoutMilliseconds);
                        result.ResponseReceived=true;result.ResponseBytes=response.Length;result.Stage="server_signature";
                        VerifyResponse(response,Hex(ServerModulus));result.ServerSignatureVerified=true;result.Stage="signed_challenge_received";
                    }
                } catch(InvalidDataException ex){result.Error=ex.Message;}
                catch(TimeoutException){result.Error="timeout";}
                catch(EndOfStreamException){result.Error="connection_closed_before_response";}
                catch(SocketException ex){result.Error="socket_"+ex.SocketErrorCode.ToString();}
                catch(IOException ex){var inner=ex.InnerException as SocketException;result.Error=inner==null?"io_failure":"socket_"+inner.SocketErrorCode.ToString();}
                catch(Exception ex){result.Error=ex.GetType().Name;}
            }
            result.Milliseconds=watch.ElapsedMilliseconds;return result;
        }
        static void ExpectRejected(Action action){try{action();}catch(InvalidDataException){return;}throw new Exception("Malformed packet accepted");}
        public static int SelfTest() {
            int cases=0;
            ExpectRejected(delegate{BodySize(new byte[]{0,0,0,0});});cases++;
            ExpectRejected(delegate{BodySize(new byte[]{0,0,0,3});});cases++;
            ExpectRejected(delegate{BodySize(new byte[]{0,1,0,1});});cases++;
            ExpectRejected(delegate{BodySize(new byte[]{255,255,255,255});});cases++;
            if(BodySize(new byte[]{0,1,0,0})!=65532)throw new Exception("Maximum packet boundary failed");cases++;
            ExpectRejected(delegate{Parse(new byte[]{0x80});});cases++;
            ExpectRejected(delegate{Parse(new byte[]{0x52,0xff,0xff,0xff,0x7f});});cases++;
            ExpectRejected(delegate{Parse(new byte[]{0});});cases++;
            ExpectRejected(delegate{Parse(new byte[]{0x53});});cases++;
            ExpectRejected(delegate{Parse(new byte[]{0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02});});cases++;
            ExpectRejected(delegate{RequiredBytes(Parse(new byte[]{0x52,0,0x52,0}),10);});cases++;
            ExpectRejected(delegate{VerifyResponse(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK"),Hex(ServerModulus));});cases++;
            using(var rsa=new RSACryptoServiceProvider(2048)){
                rsa.PersistKeyInCsp=false;
                byte[] remote=ToBigEndian(BigInteger.ModPow(new BigInteger(2),new BigInteger(12345),FromBigEndian(Hex(DhPrime))));
                byte[] signature=rsa.SignData(remote,HashAlgorithmName.SHA1,RSASignaturePadding.Pkcs1);
                byte[] dh=Message(delegate(Stream s){Bytes(s,10,remote);Integer(s,20,1);Bytes(s,30,signature);});
                byte[] crypto=Message(delegate(Stream s){Bytes(s,10,dh);});
                byte[] challenge=Message(delegate(Stream s){Bytes(s,10,crypto);});
                byte[] packet=Message(delegate(Stream s){Bytes(s,10,challenge);});
                VerifyResponse(packet,rsa.ExportParameters(false).Modulus);cases++;
                packet[packet.Length-1]^=1;
                ExpectRejected(delegate{VerifyResponse(packet,rsa.ExportParameters(false).Modulus);});cases++;
            }
            if(IsPublic(IPAddress.Parse("127.0.0.1")) || IsPublic(IPAddress.Parse("192.168.1.1")) || !IsPublic(IPAddress.Parse("35.186.224.26")))throw new Exception("Public address validation failed");cases++;
            byte[] hello=Hello();
            uint size=((uint)hello[2]<<24)|((uint)hello[3]<<16)|((uint)hello[4]<<8)|hello[5];
            if(hello[0]!=0 || hello[1]!=4 || size!=hello.Length)throw new Exception("Invalid ClientHello frame");cases++;
            return cases;
        }
    }
}