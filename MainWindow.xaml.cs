using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Timers;
using System.Collections;
using System.ComponentModel;

namespace SystemMonitor
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// Author Gareth Tucker
    /// 25-06-2019
    /// Version 0.2
    /// This is a the main window which displays information about a computer system
    /// </summary>
    public partial class MainWindow : Window
    {
        /// <summary>
        /// 
        /// </summary>
        public MainWindow()
        {
            SplashScreen splash = new SplashScreen("SplashScreen1.png");
            splash.Show(false);
            splash.Close(TimeSpan.FromSeconds(1));
            InitializeComponent();
            
        }


        private static uint? maxCpuSpeed = null;
        public static ArrayList report = new ArrayList();
        private bool sysState = true;

        public static ArrayList Report { get => report; set => report = value; }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static uint MaxCpuSpeed()
        {
            return maxCpuSpeed ?? (maxCpuSpeed = GetMaxCpuSpeed()).Value;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private static uint? GetMaxCpuSpeed()
        {
            var managementObject = new ManagementObject("Win32_Processor.DeviceID='CPU0'");
            {
                var sp = (uint)(managementObject["MaxClockSpeed"]);
                return sp;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        private void CurrentCPU()
        {
            Double currentClock = 0.0;
            
            try
            {
                using (ManagementObject mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
                { 
                    currentClock += Convert.ToDouble(mo["CurrentClockSpeed"]);
                    //actualCpuTxt.Text = currentClock.ToString();
                    Console.WriteLine("Current clock" + currentClock);
                    mo.Dispose();
                    currentClock = 0.0;
                }    
            }
            catch (Exception e)
            {
                Console.WriteLine("cpu freq not found");
            }
        }
        /// <summary>
        /// gets total ram in system
        /// </summary>
        private void DisplayInstalledRam()
        {
            UInt64 SizeinKB = 0;
            UInt64 SizeinMB = 0;
            UInt64 SizeinGB = 0;
            string Query = "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(Query);
            foreach (ManagementObject WniPART in searcher.Get())
            {
                SizeinKB = Convert.ToUInt64(WniPART.Properties["TotalPhysicalMemory"].Value);
                SizeinMB = SizeinKB / 1024/1024;
                SizeinGB = SizeinMB / 1024;
                Console.WriteLine("Size in KB: {0}, Size in MB: {1}, Size in GB: {2}", SizeinKB, SizeinMB, SizeinGB);
                
            }
            ramTxt.Text = SizeinMB.ToString();
            report.Add(SizeinMB.ToString());
        }
        /// <summary>
        /// gets total ram in system
        /// </summary>
        private void DisplayTotalRam()
        {
            UInt64 SizeinKB = 0;
            UInt64 SizeinMB = 0;
            UInt64 SizeinGB = 0;
            string Query = "SELECT MaxCapacity FROM Win32_PhysicalMemoryArray";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(Query);
            foreach (ManagementObject WniPART in searcher.Get())
            {
                SizeinKB = Convert.ToUInt64(WniPART.Properties["MaxCapacity"].Value);
                SizeinMB = SizeinKB / 1024;
                SizeinGB = SizeinMB / 1024;
                Console.WriteLine("Size in KB: {0}, Size in MB: {1}, Size in GB: {2}", SizeinKB, SizeinMB, SizeinGB);

            }
            maxMemtxt.Text = SizeinGB.ToString();
            report.Add(SizeinGB.ToString());
        }
        /// <summary>
        /// get motherboard manufacturer
        /// </summary>
        /// <returns></returns>
        public void GetMotherBoardMan()
        {
            string mbInfo = String.Empty;
            string test = String.Empty;
            try
            {
                //Get motherboard's serial number 
                ManagementObjectSearcher mbs = new ManagementObjectSearcher("Select * From Win32_BaseBoard");
                foreach (ManagementObject mo in mbs.Get())
                {
                    mbInfo += mo["Manufacturer"].ToString();
                    test += mo["Product"].ToString();
                    report.Add(mbInfo.ToString());
                    report.Add(test.ToString());                    
                }
            }
            catch(Exception e)
            {
                if (mbInfo.Equals(null) || mbInfo.Length == 0)
                {
                    moboIDTxt.Text = "Not Found";
                }         
            }
            {
                moboIDTxt.Text = mbInfo.ToString();
                modelTxt.Text = test.ToString();
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void GetFreq_Click(object sender, RoutedEventArgs e)
        {
            Freq();
        }
        /// <summary>
        /// gets os Version
        /// </summary>
        private void OsVersion()
        {
            string r = "";
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    ManagementObjectCollection information = searcher.Get();
                    if (information != null)
                    {
                        foreach (ManagementObject obj in information)
                        {
                            r = obj["Caption"].ToString() + " - " + obj["OSArchitecture"].ToString();
                        }
                    }
                    r = r.Replace("NT 5.1.2600", "XP");
                    r = r.Replace("NT 5.2.3790", "Server 2003");
                    osNameTxt.Text = r;
                    report.Add(r.ToString());
                }
            }
            catch (Exception e)
            {
                osNameTxt.Text = "Not Found" +e;
            }
        }
        /// <summary>
        /// get ip address and network card for multiple nets and vms
        /// not currently in use
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public void DisplayIPAddresses()
        {
            StringBuilder sb = new StringBuilder();
            string returnAddress = String.Empty;

            // Get a list of all network interfaces (usually one per network card, dialup, and VPN connection)
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface network in networkInterfaces)
            {
                // Read the IP configuration for each network
                IPInterfaceProperties properties = network.GetIPProperties();

                if (network.NetworkInterfaceType == NetworkInterfaceType.Ethernet || 
                    network.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&                   
                       network.OperationalStatus == OperationalStatus.Up ||
                       network.OperationalStatus == OperationalStatus.Down &&
                       !network.Description.ToLower().Contains("virtual") &&
                       !network.Description.ToLower().Contains("pseudo"))
                {
                    // Each network interface may have multiple IP addresses
                    foreach (IPAddressInformation address in properties.UnicastAddresses)
                    {                       
                        // We're only interested in IPv4 addresses for now
                        if (address.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;
                        // Ignore loopback addresses (e.g., 127.0.0.1)
                        if (IPAddress.IsLoopback(address.Address))
                            continue;
                        returnAddress = address.Address.ToString();
                        //Console.WriteLine(address.Address.ToString() + " (" + network.Name + " - " + network.Description + ")");
                        sb.Append(returnAddress.ToString() + " (" + network.Name + " - " + network.Description + ")"+"\n");
                    }
                    ipTxt.Text = sb.ToString();
                    report.Add(sb.ToString());
                }
            }
        }
        /// <summary>
        /// Get local IP
        /// </summary>
        public void LocalIp()
        {
            string localIP;
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 65530);
                IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                localIP = endPoint.Address.ToString();
            }
            ipListTxt.Text = localIP.ToString();
            report.Add(localIP.ToString());
        }
        /// <summary>
        /// get cpu information
        /// </summary>
        private void CpuID()
        {
            String cpuID = "";
            String caption = "";
            String l2CacheSize = "";
            String l3CacheSize = "";
            //Get motherboard's serial number
            try
            {
                ManagementObjectSearcher mbs = new ManagementObjectSearcher("Select * From Win32_Processor");
                foreach (ManagementObject mo in mbs.Get())
                {
                    //Console.WriteLine(mo["Name"].ToString());
                    cpuID += mo["Name"].ToString();
                    caption += mo["Caption"].ToString();
                    l2CacheSize += mo["L2CacheSize"].ToString();
                    l3CacheSize += mo["L3CacheSize"].ToString();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                cpuIDtxt.Text = "Not Found";
                l2cacheSTxt.Text = "Not Found";
                l2CacheZTxt.Text = "Not Found";
            }
            cpuIDtxt.Text = cpuID.ToString() +" "+ caption.ToString();
            l2CacheZTxt.Text = l2CacheSize.ToString();
            l2cacheSTxt.Text = l3CacheSize.ToString();
            report.Add(cpuID.ToString());
            report.Add(l2CacheSize.ToString());
            report.Add(l3CacheSize.ToString());
        }
        /// <summary>
        /// get gpu info
        /// </summary>
        private void GpuInfo()
        {
            string gpuName = string.Empty;
            string gpuRefresh = string.Empty;
            try
            {
                ManagementObjectSearcher mbs = new ManagementObjectSearcher("Select * from Win32_VideoController");
                foreach(ManagementObject mo in mbs.Get())
                {
                    Console.WriteLine("name " + mo["Name"]);
                    gpuName += mo["Name"];
                    gpuRefresh += mo["MaxRefreshRate"];
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }
            gpuTxt.Text = gpuName.ToString();
            gpuRefreshTxt.Text = gpuRefresh.ToString();
            report.Add(gpuName.ToString());
            report.Add(gpuRefresh.ToString());
        }
        /// <summary>
        /// displays bios version
        /// </summary>
        private void BiosVersion()
        {
            string manu = string.Empty;
            string bios = string.Empty;
            string date = string.Empty;
            try
            {
                ManagementObjectSearcher mbs = new ManagementObjectSearcher("Select * From Win32_BIOS");
                foreach (ManagementObject mo in mbs.Get())
                {
                    manu += mo["Manufacturer"].ToString();
                    bios += mo["Caption"].ToString();
                    report.Add(manu.ToString());
                    report.Add(bios.ToString());
                }
            }
            catch (Exception e)
            {
                biosTxt.Text = "Not Found";
            }           
            biosTxt.Text = manu.ToString() + " AGESA " + bios.ToString();
        }
        /// <summary>
        /// 
        /// </summary>
        private void Freq()
        {
            MaxCpuSpeed();
            cpuFreq.Text = maxCpuSpeed.ToString();
            int coreCount = Environment.ProcessorCount;
            coreCountTxt.Text = coreCount.ToString();
            coreThreadText.Text = (coreCount / 2 + "c/" + coreCount+"t");           
            CpuID();
            GpuInfo();
            DisplayInstalledRam();
            DisplayTotalRam();
            userNameTxt.Text = Environment.UserName;
            OsVersion();
            sysNameTxt.Text = Environment.MachineName;
            is64BitTxt.Text = Environment.Is64BitOperatingSystem.ToString();            
            GetMotherBoardMan();          
            DisplayIPAddresses();
            LocalIp();
            BiosVersion();
            actualCPU();
        }
        /// <summary>
        /// Exits the program
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CloseProgram_Click(object sender, RoutedEventArgs e)
        {
            sysState = true;
            Environment.Exit(0);
        }
        /// <summary>
        /// 
        /// </summary>
        public static void WriteToFile()
        {
            string userName = Environment.UserName.ToString();
            //string location = "\Desktop\";
            //System.IO.File.WriteAllText(@"C:\Users\"+userName+"\Desktop\Report.txt", report.ToString());
        }

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {
            Window1 rep = new Window1();
            rep.ShowDialog();
        }
      /// <summary>
      /// begins background worker to report current cpu clock speeds.
      /// </summary>
     private void actualCPU()
        {
           int i = 100;
            BackgroundWorker bw = new BackgroundWorker();
            bw.RunWorkerAsync(true);
            for (i = 0; i > 100; i--)
            {
                cpuReport();
                i--;
            }
           
        }
        /// <summary>
        /// called by background worker to get the value of the current cpu clock speeds
        /// </summary>
        private void cpuReport()
        {
            double actualCPU = 0.0;
            try
            {
                using (ManagementObject mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
                {
                    actualCPU += Convert.ToDouble(mo["CurrentClockSpeed"]);
                    actualCpuTxt.Text = actualCPU.ToString();
                    //Console.WriteLine("Current clock" + currentClock);
                    mo.Dispose();
                    //currentClock = 0.0;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("cpu freq not found");
            }
        }
        
    }
}
