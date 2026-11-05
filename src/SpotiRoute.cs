using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("SpotiRoute")]
[assembly: AssemblyDescription("Spotify network route maintenance")]
[assembly: AssemblyCompany("SpotiRoute contributors")]
[assembly: AssemblyProduct("SpotiRoute")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]

namespace SpotiRoute {
    internal static class Program {
        internal const string Root = @"C:\ProgramData\SpotifyNetworkGuard";
        internal const string TaskName = "Spotify Network Guard";
        internal static readonly string[] PayloadNames = {
            "Guard.Core.ps1", "Update-SpotifyHosts.ps1", "Manage-SpotifyGuard.ps1",
            "Install-SpotifyGuard.ps1", "config.json", "manifest.json"
        };
        internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 2097152 };
        [STAThread]
        private static int Main(string[] args) {
            try {
                if (args.Length == 2 && args[0] == "--self-test") {
                    var report = new Dictionary<string,object>();
                    VerifyPayload();
                    report["success"] = true;
                    report["version"] = "0.1.0";
                    report["embedded_files"] = PayloadNames;
                    report["payload_verified"] = true;
                    report["installed"] = File.Exists(Path.Combine(Root,"owner.json"));
                    report["live_status_readable"] = ReadJson(Path.Combine(Root,@"data\status.json")) != null;
                    File.WriteAllText(args[1],Json.Serialize(report),new UTF8Encoding(false));
                    return 0;
                }
                if (args.Length == 2 && args[0] == "--action") return ExecuteAction(args[1]);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainWindow());
                return 0;
            } catch (Exception ex) {
                if(args.Length == 2 && args[0] == "--self-test") {
                    File.WriteAllText(args[1],Json.Serialize(new { success=false, error=ex.Message }),new UTF8Encoding(false));
                } else {
                    MessageBox.Show(ex.Message,"SpotiRoute",MessageBoxButtons.OK,MessageBoxIcon.Error);
                }
                return 1;
            }
        }
        internal static Dictionary<string,object> ReadJson(string path) {
            try {
                var f=new FileInfo(path);
                if(!f.Exists || f.Length>2097152) return null;
                lock(Json) return Json.DeserializeObject(File.ReadAllText(path,Encoding.UTF8)) as Dictionary<string,object>;
            } catch { return null; }
        }
        internal static object Get(Dictionary<string,object> d,string key) {
            object value;return d!=null && d.TryGetValue(key,out value)?value:null;
        }
        internal static bool Bool(Dictionary<string,object> d,string key) {
            return Object.Equals(Get(d,key),true);
        }
        internal static string Text(Dictionary<string,object> d,string key) {
            object v=Get(d,key);return v==null?"":Convert.ToString(v);
        }
        internal static Dictionary<string,object> Dict(Dictionary<string,object> d,string key) {
            return Get(d,key) as Dictionary<string,object>;
        }
        internal static byte[] Resource(string name) {
            using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("SpotiRoute.Payload."+name)) {
                if(input==null) throw new InvalidOperationException("В сборке отсутствует файл "+name);
                using(var output=new MemoryStream()) {input.CopyTo(output);return output.ToArray();}
            }
        }
        internal static string Hash(byte[] bytes) {
            using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","");
        }
        internal static void VerifyPayload() {
            var manifest=Json.DeserializeObject(Encoding.UTF8.GetString(Resource("manifest.json")).TrimStart('\uFEFF')) as Dictionary<string,object>;
            var hashes=Dict(manifest,"Hashes");
            if(hashes==null) throw new InvalidOperationException("Повреждён манифест сборки.");
            foreach(var name in new[]{"Guard.Core.ps1","Update-SpotifyHosts.ps1","Manage-SpotifyGuard.ps1","Install-SpotifyGuard.ps1","config.json"}) {
                if(!String.Equals(Hash(Resource(name)),Text(hashes,name),StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Не совпадает контрольная сумма "+name);
            }
        }
        internal static bool IsAdministrator() {
            using(var id=WindowsIdentity.GetCurrent()) return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        internal static int RunAction(string action) {
            if(action=="Check" && TryRunTask()) return 0;
            if(!IsAdministrator()) {
                var start=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--action "+action);
                start.UseShellExecute=true;start.Verb="runas";start.WindowStyle=ProcessWindowStyle.Hidden;
                using(var helper=Process.Start(start)) {helper.WaitForExit();return helper.ExitCode;}
            }
            return ExecuteAction(action);
        }
        private static int ExecuteAction(string action) {
            if(Array.IndexOf(new[]{"Install","Check","Enable","Disable","Restore","Uninstall"},action)<0)
                throw new ArgumentException("Неизвестное действие.");
            if(!IsAdministrator()) return RunAction(action);
            if(action=="Install") return InstallPayload();
            ValidateInstallation();
            string manager=Path.Combine(Root,"Manage-SpotifyGuard.ps1");
            if(!File.Exists(manager)) throw new InvalidOperationException("Фоновый компонент ещё не установлен.");
            return RunPowerShell(manager,"-Action "+action);
        }
        private static int RunPowerShell(string script,string arguments) {
            string native=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),@"System32\WindowsPowerShell\v1.0\powershell.exe");
            var start=new ProcessStartInfo(native,"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+script+"\" "+arguments);
            start.UseShellExecute=false;start.CreateNoWindow=true;start.WindowStyle=ProcessWindowStyle.Hidden;
            using(var process=Process.Start(start)) {process.WaitForExit();return process.ExitCode;}
        }
        private static int InstallPayload() {
            if(File.Exists(Path.Combine(Root,"owner.json")) && !Object.Equals(Get(ReadJson(Path.Combine(Root,"owner.json")),"InstallationComplete"),false) && TaskState()>=1) {
                ValidateInstallation();
                // The existing engine remains in place; this release does not silently replace it.
                var existing=ReadJson(Path.Combine(Root,"owner.json"));
                if(Text(existing,"Product")!="SpotifyNetworkGuard") throw new InvalidOperationException("Папка компонента принадлежит другой программе.");
                return 0;
            }
            VerifyPayload();
            string stagingBase=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"SpotiRoute.Staging");
            var security=new DirectorySecurity();
            security.SetAccessRuleProtection(true,false);
            security.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
            foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"}) security.AddAccessRule(
                new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            if(Directory.Exists(stagingBase)) ValidateProtectedPath(stagingBase,true);
            Directory.CreateDirectory(stagingBase,security);
            if((File.GetAttributes(stagingBase)&FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("Небезопасная папка установки.");
            Directory.SetAccessControl(stagingBase,security);
            string stage=Path.Combine(stagingBase,Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stage,security);
            try {
                foreach(var name in PayloadNames) File.WriteAllBytes(Path.Combine(stage,name),Resource(name));
                int code=RunPowerShell(Path.Combine(stage,"Install-SpotifyGuard.ps1"),"-PackageRoot \""+stage+"\"");
                var result=ReadJson(Path.Combine(stage,"installation.json"));
                if(code!=0 || !Bool(result,"Success")) throw new InvalidOperationException("Установка не завершена. "+Text(result,"Error"));
                File.Copy(Path.Combine(stage,"installation.json"),Path.Combine(Root,@"data\setup-result.json"),true);
                return 0;
            } finally {
                foreach(var name in PayloadNames) {string p=Path.Combine(stage,name);if(File.Exists(p)) File.Delete(p);}
                foreach(var name in new[]{"installation.json","installation.json.previous","task.xml"}) {string p=Path.Combine(stage,name);if(File.Exists(p)) File.Delete(p);}
                try {Directory.Delete(stage,false);} catch(IOException) { }
            }
        }
        private static void ValidateProtectedPath(string path,bool directory) {
            if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
                throw new InvalidOperationException("Папка или файл компонента перенаправлены: "+path);
            FileSystemSecurity acl=directory?(FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);
            string current=WindowsIdentity.GetCurrent().User.Value;
            Func<string,bool> trusted=sid=>sid=="S-1-5-18" || sid=="S-1-5-32-544" || (sid==current && IsAdministrator());
            if(!trusted(acl.GetOwner(typeof(SecurityIdentifier)).Value))
                throw new InvalidOperationException("Неподходящий владелец компонента: "+path);
            var writes=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership|FileSystemRights.DeleteSubdirectoriesAndFiles;
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                if(rule.AccessControlType==AccessControlType.Allow && (rule.FileSystemRights&writes)!=0 && !trusted(rule.IdentityReference.Value))
                    throw new InvalidOperationException("Компонент доступен на запись обычным пользователям: "+path);
        }
        private static void ValidateInstallation() {
            ValidateProtectedPath(Root,true);
            foreach(string name in new[]{"owner.json","Guard.Core.ps1","Update-SpotifyHosts.ps1","Manage-SpotifyGuard.ps1","config.json"})
                ValidateProtectedPath(Path.Combine(Root,name),false);
            ValidateProtectedPath(Path.Combine(Root,"data"),true);
            if(Text(ReadJson(Path.Combine(Root,"owner.json")),"Product")!="SpotifyNetworkGuard")
                throw new InvalidOperationException("Папка компонента принадлежит другой программе.");
        }
        internal static bool TryRunTask() {
            try {
                dynamic scheduler=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
                scheduler.Connect();
                dynamic task=scheduler.GetFolder("\\").GetTask(TaskName);
                task.Run(null);return true;
            } catch {return false;}
        }
        internal static int TaskState() {
            try {
                dynamic scheduler=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
                scheduler.Connect();dynamic task=scheduler.GetFolder("\\").GetTask(TaskName);
                return (int)task.State;
            } catch {return -1;}
        }
    }
    internal sealed class RouteIcon : Control {
        public RouteIcon() {DoubleBuffered=true;Size=new Size(54,54);}
        protected override void OnPaint(PaintEventArgs e) {
            base.OnPaint(e);var g=e.Graphics;g.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using(var pen=new Pen(Color.FromArgb(80,225,150),4)) {
                g.DrawLine(pen,13,38,13,20);g.DrawArc(pen,13,9,27,22,180,180);g.DrawLine(pen,40,20,40,35);
            }
            using(var fill=new SolidBrush(Color.FromArgb(80,225,150))) {g.FillEllipse(fill,8,33,10,10);g.FillEllipse(fill,35,31,10,10);}
        }
    }
    internal sealed class MainWindow : Form {
        private readonly Color Bg=Color.FromArgb(18,23,30), Card=Color.FromArgb(29,37,47), Muted=Color.FromArgb(163,178,195), Green=Color.FromArgb(89,224,156);
        private Label titleStatus,detailStatus,lastCheck,lastResult,artStatus,activityStatus,connectStatus,notice;
        private Button check,enabled,install;
        private readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
        private volatile bool refreshPending;
        private bool busy,autoEnabled,componentInstalled;
        public MainWindow() {
            Text="SpotiRoute";ClientSize=new Size(800,570);MinimumSize=new Size(820,610);
            BackColor=Bg;ForeColor=Color.FromArgb(235,241,246);Font=new Font("Segoe UI",10);
            AutoScaleDimensions=new SizeF(96,96);AutoScaleMode=AutoScaleMode.Dpi;StartPosition=FormStartPosition.CenterScreen;
            try{Icon=Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);}catch{}
            Controls.Add(new RouteIcon {Location=new Point(24,24)});
            LabelAt("SpotiRoute",88,23,580,34,24,FontStyle.Bold);
            LabelAt("Обложки, Spotify Connect и маршрут активности Discord",90,65,650,24,10,FontStyle.Regular).ForeColor=Muted;
            var statusPanel=PanelAt(24,108,752,133);
            titleStatus=LabelAt("Загружаем состояние…",20,17,700,32,18,FontStyle.Bold,statusPanel);
            detailStatus=LabelAt("",21,57,700,23,10,FontStyle.Regular,statusPanel);detailStatus.ForeColor=Muted;
            lastResult=LabelAt("",21,87,700,22,10,FontStyle.Regular,statusPanel);lastResult.ForeColor=Muted;
            var left=PanelAt(24,257,366,84);var right=PanelAt(406,257,370,84);
            LabelAt("Последняя проверка",16,10,320,22,10,FontStyle.Regular,left).ForeColor=Muted;
            lastCheck=LabelAt("—",16,36,320,32,16,FontStyle.Bold,left);
            LabelAt("Автоматический режим",16,10,330,22,10,FontStyle.Regular,right).ForeColor=Muted;
            LabelAt("Каждые 2 минуты",16,36,330,32,16,FontStyle.Bold,right);
            artStatus=LabelAt("Обложки  ·  —",26,358,240,26,10,FontStyle.Regular);
            activityStatus=LabelAt("Discord  ·  —",280,358,260,26,10,FontStyle.Regular);
            connectStatus=LabelAt("Spotify Connect  ·  —",552,358,225,26,10,FontStyle.Regular);
            check=ButtonAt("Проверить сейчас",24,403,208,true);check.Click+=(s,e)=>DoAction("Check");
            enabled=ButtonAt("Приостановить",248,403,208,false);enabled.Click+=(s,e)=>DoAction(autoEnabled?"Disable":"Enable");
            var log=ButtonAt("Открыть журнал",472,403,208,false);log.Click+=(s,e)=>OpenLog();
            install=ButtonAt("Установить компонент",24,457,208,false);install.Click+=(s,e)=>DoAction("Install");
            var restore=ButtonAt("Вернуть прежние адреса",248,457,245,false);
            restore.Click+=(s,e)=>{if(MessageBox.Show(this,"Отключить автообновление и вернуть только маршруты Spotify к состоянию до установки?","SpotiRoute",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes)DoAction("Restore");};
            var uninstall=ButtonAt("Удалить задачу",509,457,171,false);
            uninstall.Click+=(s,e)=>{if(MessageBox.Show(this,"Удалить фоновую задачу? Текущие адреса и резервные копии сохранятся.","SpotiRoute",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes)DoAction("Uninstall");};
            notice=LabelAt("При изменении системных настроек Windows может запросить права администратора.",26,519,748,38,9,FontStyle.Regular);notice.ForeColor=Muted;
            LabelAt("0.1.0 beta",687,466,88,22,9,FontStyle.Regular).ForeColor=Muted;
            timer.Interval=3000;timer.Tick+=(s,e)=>RefreshState();timer.Start();
            Shown+=(s,e)=>RefreshState();
        }
        private Panel PanelAt(int x,int y,int w,int h) {
            var p=new Panel {Location=new Point(x,y),Size=new Size(w,h),BackColor=Card};Controls.Add(p);return p;
        }
        private Label LabelAt(string text,int x,int y,int w,int h,int size,FontStyle style,Control parent=null) {
            var label=new Label {Text=text,Location=new Point(x,y),Size=new Size(w,h),Font=new Font("Segoe UI",size,style),ForeColor=ForeColor,AutoEllipsis=true};
            (parent??this).Controls.Add(label);return label;
        }
        private Button ButtonAt(string text,int x,int y,int w,bool primary) {
            var b=new Button {Text=text,Location=new Point(x,y),Size=new Size(w,40),FlatStyle=FlatStyle.Flat,BackColor=primary?Green:Card,ForeColor=primary?Bg:ForeColor,Cursor=Cursors.Hand};
            b.FlatAppearance.BorderSize=0;Controls.Add(b);return b;
        }
        private void RefreshState() {
            if(refreshPending || IsDisposed)return;refreshPending=true;
            ThreadPool.QueueUserWorkItem(delegate {
                var status=Program.ReadJson(Path.Combine(Program.Root,@"data\status.json"));
                var control=Program.ReadJson(Path.Combine(Program.Root,@"data\control-result.json"));
                var owner=Program.ReadJson(Path.Combine(Program.Root,"owner.json")); bool installed=owner!=null && !Object.Equals(Program.Get(owner,"InstallationComplete"),false);
                int state=Program.TaskState();
                try {if(!IsDisposed && IsHandleCreated)BeginInvoke((Action)delegate {ApplyState(status,control,installed,state);refreshPending=false;});}
                catch {refreshPending=false;}
            });
        }
        private bool EndpointOk(Dictionary<string,object> status,string domain) {
            if(Program.Bool(status,"Healthy"))return true;
            var before=Program.Dict(status,"HealthBefore");return Program.Bool(Program.Dict(before,domain),"Ok");
        }
        private void ApplyState(Dictionary<string,object> status,Dictionary<string,object> control,bool installed,int taskState) {
            componentInstalled=installed;
            DateTime checkedAt;bool hasTime=DateTime.TryParse(Program.Text(status,"FinishedUtc"),null,System.Globalization.DateTimeStyles.RoundtripKind,out checkedAt);
            bool recent=hasTime && DateTime.UtcNow-checkedAt.ToUniversalTime()<TimeSpan.FromMinutes(6);
            string action=Program.Text(control,"Action");
            if(Program.Bool(control,"Success") && action=="Uninstall") installed=false;
            bool disabledByControl=Program.Bool(control,"Success") && (action=="Disable" || action=="Restore" || action=="Uninstall");
            autoEnabled=taskState>=0 ? taskState!=1 && taskState!=0 : recent && !disabledByControl;
            bool healthy=Program.Bool(status,"Healthy");
            if(!installed){titleStatus.Text="Компонент ещё не установлен";titleStatus.ForeColor=Muted;detailStatus.Text="Установите фоновую проверку маршрутов Spotify.";}
            else if(!autoEnabled){titleStatus.Text="Автопроверка приостановлена";titleStatus.ForeColor=Color.FromArgb(243,194,103);detailStatus.Text="Последние адреса сохранены. Проверку можно включить снова.";}
            else if(!recent){titleStatus.Text="Состояние устарело";titleStatus.ForeColor=Color.FromArgb(243,194,103);detailStatus.Text="Свежая проверка ещё не завершилась. Запросите её кнопкой ниже.";}
            else if(healthy){titleStatus.Text="Маршруты работают";titleStatus.ForeColor=Green;detailStatus.Text="Рабочие адреса сохраняются. Замена допускается только после проверки.";}
            else {titleStatus.Text="Обнаружены ошибки соединения";titleStatus.ForeColor=Color.FromArgb(243,194,103);detailStatus.Text="Проверяем повторный сбой и ищем подтверждённую замену.";}
            lastCheck.Text=hasTime?checkedAt.ToLocalTime().ToString("dd.MM · HH:mm:ss"):"Ещё не выполнялась";
            lastResult.Text=Program.Bool(status,"Changed")?"Последний цикл обновил адреса.":installed?"Последний цикл сохранил адреса.":"Фоновая задача работает без открытого окна программы.";
            artStatus.Text="Обложки  ·  "+(status==null?"—":EndpointOk(status,"i.scdn.co")&&EndpointOk(status,"image-cdn-ak.spotifycdn.com")?"доступны":"есть сбой");
            activityStatus.Text="Discord  ·  "+(status==null?"—":EndpointOk(status,"api.spotify.com")&&EndpointOk(status,"dealer.spotify.com")?"маршрут доступен":"есть сбой");
            connectStatus.Text="Spotify Connect  ·  "+(status==null?"—":EndpointOk(status,"gew1-spclient.spotify.com")&&EndpointOk(status,"gew1-dealer.spotify.com")&&EndpointOk(status,"spclient.wg.spotify.com")?"доступен":"есть сбой");
            check.Enabled=installed&&!busy;enabled.Enabled=installed&&!busy;
            enabled.Text=autoEnabled?"Приостановить":"Включить";
            install.Enabled=!installed&&!busy;install.Text=installed?"Компонент установлен":"Установить компонент";
        }
        private void DoAction(string action) {
            if(busy)return;busy=true;check.Enabled=false;enabled.Enabled=false;install.Enabled=false;
            notice.Text=action=="Check"?"Запрашиваем проверку…":"Выполняем действие…";
            ThreadPool.QueueUserWorkItem(delegate {
                string error=null;
                try {int code=Program.RunAction(action);if(code!=0)error="Действие не завершилось. Код "+code+". Подробности — в журнале компонента.";}
                catch(System.ComponentModel.Win32Exception ex){error=ex.NativeErrorCode==1223?"Запрос прав администратора отменён.":ex.Message;}
                catch(Exception ex){error=ex.Message;}
                if(!IsDisposed)BeginInvoke((Action)delegate {busy=false;notice.Text=error??(action=="Check"?"Проверка запрошена. Состояние обновится автоматически.":"Готово.");RefreshState();});
            });
        }
        private void OpenLog() {
            string file=Path.Combine(Program.Root,@"data\events.jsonl");
            if(File.Exists(file))Process.Start(new ProcessStartInfo("notepad.exe","\""+file+"\""){UseShellExecute=true});
            else MessageBox.Show(this,"Журнал появится после установки и первой проверки.","SpotiRoute");
        }
        protected override void Dispose(bool disposing){if(disposing)timer.Dispose();base.Dispose(disposing);}
    }
}
