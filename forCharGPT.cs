using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Windows.Forms;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.Management;
using Microsoft.Win32;


namespace P215test
{

    public partial class P215Test : Form
    {
        [DllImport("Kernel32.dll")] private static extern Boolean AllocConsole();


        private static Mutex _pool = new Mutex();

        readonly public static int _pingsent = 420;
        int _timeLeft = 10;
        int _counter;
        int _secondCounter;
        bool _flagFor;
        private static bool _killThread = false;

        List<CheckBox> myCheckBoxs = new List<CheckBox>();     // = new List<CheckBox>;
        List<Label> myLabel = new List<Label>();
        static List<int> myState = new List<int>();
        public P215Test()
        {

            for (int i = 0; i < 16; i++)
            {
                myState.Add(0);

            }

            InitializeComponent();

            #region initForms

            myCheckBoxs.Add(checkBox1);
            myCheckBoxs.Add(checkBox2);
            myCheckBoxs.Add(checkBox3);
            myCheckBoxs.Add(checkBox4);
            myCheckBoxs.Add(checkBox5);
            myCheckBoxs.Add(checkBox6);
            myCheckBoxs.Add(checkBox7);
            myCheckBoxs.Add(checkBox8);
            myCheckBoxs.Add(checkBox9);
            myCheckBoxs.Add(checkBox10);
            myCheckBoxs.Add(checkBox11);
            myCheckBoxs.Add(checkBox12);
            myCheckBoxs.Add(checkBox13);
            myCheckBoxs.Add(checkBox14);
            myCheckBoxs.Add(checkBox15);
            myCheckBoxs.Add(checkBox16);

            myLabel.Add(label2);
            myLabel.Add(label3);
            myLabel.Add(label4);
            myLabel.Add(label5);
            myLabel.Add(label6);
            myLabel.Add(label7);
            myLabel.Add(label8);
            myLabel.Add(label9);
            myLabel.Add(label10);
            myLabel.Add(label11);
            myLabel.Add(label12);
            myLabel.Add(label13);
            myLabel.Add(label14);
            myLabel.Add(label15);
            myLabel.Add(label16);
            myLabel.Add(label17);

            foreach (Label t in myLabel)
            {
                t.Visible = false;
                t.Text = "";
            }
            #endregion
        }

        private static void GetNull()
        {
            lock (Locker)
            {


                for (int i = 0; i < 16; i++)
                {
                    myState[i] = 0;
                }
                Thread.Sleep(10);
            }
        }


        static readonly object Locker = new object();

        private void Button3Click(object sender, EventArgs e)
        {
            //------------------------------------------ начальная инициализация

            //string macDest = GetMacFromIp("192.168.100.100");

            //if (macDest == "fail")
            //{
            //    MessageBox.Show(@"Ноутбук не подкюлчен или неправильно заданы начальные конфигурации сети ноутбука");
            //    return;
            //}


            //------------------------------------------)

            for (int i = 0; i < myCheckBoxs.Count; i++)
            {
                if (myCheckBoxs[i].Checked)
                {
                    myLabel[i].Visible = true;
                    myLabel[i].ForeColor = Color.Black;
                }
            }

            if (button3.Text == @"ОПРОС")
            {
                GetNull();
                button3.Enabled = false;            ///////////////////////////////////

                timer1.Start();

                _flagFor = false;

                if (myCheckBoxs.Where(t => t.Checked).Any())
                {
                    _flagFor = true;
                }

                if (_flagFor)
                {

                    button3.Text = @"СТОП";

                    for (var ii = 0; ii < myCheckBoxs.Count; ii++)
                    {
                        myCheckBoxs[ii].Enabled = false;
                        radioButton1.Enabled = false;
                        radioButton2.Enabled = false;
                        myLabel[ii].Text = "";
                    }
                    _counter = 0;
                    _secondCounter = 1;
                    _timeLeft = 10;
                    _killThread = false;
                }



                else
                {
                    MessageBox.Show(@"Порты не выбраны");
                    return;
                }

                int devNum = 0;
                /*
                foreach (var myCheckBox in myCheckBoxs)
                {
                    if (myCheckBox.Checked)
                    {
                       MyPacketForm(devNum);
                    }

                    devNum++;
                }
                 */

            }
            else
            {
                button3.Text = @"ОПРОС";
                timer1.Stop();
                radioButton1.Enabled = true;
                radioButton2.Enabled = true;
                foreach (var t in myCheckBoxs)
                    t.Enabled = true;
                _counter = 0;
                _secondCounter = 0;
                GetNull();
                _killThread = true;
                //тормозить потоки
            }

        }

        private void Timer1Tick(object sender, EventArgs e)
        {
            button3.Enabled = true;
            if (_counter >= 16)
            {
                timer1.Stop();
                return;

            }

            while (myCheckBoxs[_secondCounter].Checked != true && _secondCounter < 15)
            {
                _secondCounter++;
            }

            if (_secondCounter >= 16)
            {
                while (myCheckBoxs[_counter].Checked != true && _counter < 15)
                {
                    _counter++;
                }
                _secondCounter = _counter + 1;
                while (myCheckBoxs[_secondCounter].Checked != true && _secondCounter < 15)
                {
                    _secondCounter++;
                }

            }
            if (myCheckBoxs[_counter].Checked != true)
            {
                timer1.Stop();
                return;
            }
            if (_timeLeft == 10)
            {
                _killThread = false;
                MyPacketForm(_counter, _secondCounter);
            }
            if (_timeLeft == 1) _killThread = true;

            if (_timeLeft > 0 && _counter < 16)
            {
                // Display the new time left
                // by updating the Time Left label.
                _timeLeft = _timeLeft - 1;
                myLabel[_counter].Text = _timeLeft + @" сек";

            }
            else
            {
                _timeLeft = 10;
                if (myState[_counter] > (int)(_pingsent * 80 / 100))
                {
                    myLabel[_counter].Text = @"Работает ";// +100 * myState[_counter] / _pingsent;
                    myLabel[_counter].ForeColor = Color.Green;

                }
                else
                {
                    myLabel[_counter].Text = @"Не работает ";//+ 100 * myState[_counter] / _pingsent;
                    myLabel[_counter].ForeColor = Color.Red;
                }

                _counter++;

            }
        }

        private void Button1Click(object sender, EventArgs e)
        {
            foreach (CheckBox var in myCheckBoxs)
            {
                var.Checked = true;
            }
        }   //Выбрать все

        private void Button2Click(object sender, EventArgs e)
        {
            foreach (CheckBox var in myCheckBoxs)
            {
                var.Checked = false;
            }
        }   //Убрать все

        private void Button4Click(object sender, EventArgs e)
        {



            // webBrowser1.Navigate("192.168.0.44");
            string macDest = GetMacFromIp("192.168.100.44");

            if (macDest == "fail")
            {
                MessageBox.Show(@"Камера не найдена");
                return;
            }

            const string filename = @"iexplore";
            Process.Start(filename);

        }


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int destIP, int srcIP, byte[] pMacAddr, ref uint phyAddrLen);

        private static string GetMacFromIp(string addr)
        {
            var dst = IPAddress.Parse(addr);
            var macAddr = new byte[6];
            var macAddrLen = (uint)macAddr.Length;
            if (dst != null)
                if (SendARP(BitConverter.ToInt32(dst.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen) != 0)
                {
                    return "fail";
                }


            var str = new string[(int)macAddrLen];
            for (var i = 0; i < macAddrLen; i++)
                str[i] = macAddr[i].ToString("x2");

            return str.Aggregate("", (current, t) => current + t);
        }

        private static PacketDevice FindDevice(int num)
        {
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                return null;
            }

            PacketDevice selectedDevice = null;
            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                var device = allDevices[i];
                string desc = device.Description;
                string numbTemp;
                if (num < 9)
                    numbTemp = "#0" + (num + 1);
                else
                {
                    numbTemp = "#" + (num + 1);
                }

                if (desc.Contains(numbTemp))
                {
                    selectedDevice = allDevices[i];
                    break;
                }
            }
            return selectedDevice;
        }

        private static void MyPacketForm(int num, int numD)
        {
            PacketDevice selectedDevice = FindDevice(num);
            PacketDevice destinationDevice = FindDevice(numD);
            //PacketDevice[] devices = new PacketDevice[2];
            //devices[0] = FindDevice(num);
            //devices[1] = FindDevice(numD);
            DestinationAndSourceAddress o = new DestinationAndSourceAddress(selectedDevice, destinationDevice);

            var thread2 = new Thread(Writer);
            thread2.Start(o);
            var thread = new Thread(Reader);
            thread.Start(selectedDevice);
        }
        class DestinationAndSourceAddress
        {
            private PacketDevice source;
            private PacketDevice destination;
            public DestinationAndSourceAddress(PacketDevice o, PacketDevice d)
            {
                source = o;
                destination = d;
            }

            public PacketDevice GetSoure()
            {
                return source;
            }

            public PacketDevice GetDestination()
            {
                return destination;
            }

        }
        class GetMacAddressFromIPAddress
        {
            private const int PingTimeout = 1000;

            private static bool IsHostAccessible(string hostNameOrAddress)
            {
                var ping = new Ping();
                var buf = System.Text.Encoding.ASCII.GetBytes("ollllllllllllllllllloooooooolllllllllllllllloooooooooo222");
                PingReply reply = null;
                try
                {
                    reply = ping.Send(hostNameOrAddress, PingTimeout, buf);
                }
                catch (Exception)
                {
                    reply = null;
                }
                if (reply != null) return reply.Status == IPStatus.Success;
                return false;
            }

            #region Getting MAC from ARP
            [DllImport("iphlpapi.dll", ExactSpelling = true)]
            // ReSharper disable MemberHidesStaticFromOuterClass
            static extern int SendARP(int destIP, int srcIP, byte[] pMacAddr, ref uint phyAddrLen);
            // ReSharper restore MemberHidesStaticFromOuterClass

            public static string GetMacAddressFromArp(string hostNameOrAddress)
            {
                if (!IsHostAccessible(hostNameOrAddress)) return null;
                IPHostEntry hostEntry = Dns.GetHostEntry(hostNameOrAddress);
                if (hostEntry.AddressList.Length == 0)
                    return null;
                var macAddr = new byte[6];
                var macAddrLen = (uint)macAddr.Length;

#pragma warning disable 612, 618
                if (SendARP((int)hostEntry.AddressList[0].Address, 0, macAddr, ref macAddrLen) != 0)
#pragma warning restore 612,618
                    return null;
                var macAddressString = new StringBuilder();
                foreach (byte t in macAddr)
                {
                    if (macAddressString.Length > 0)
                        macAddressString.Append(":");
                    macAddressString.AppendFormat("{0:x2}", t);
                }
                return macAddressString.ToString();
            } // end GetMACAddressFromARP
            #endregion Getting MAC from ARP
        }



        private static void Writer(object o)
        {
            var temp = (DestinationAndSourceAddress)o;
            var selectedDevice = temp.GetSoure();
            if (selectedDevice == null)
                return;
            string addr = selectedDevice.Addresses.Count == 2 ? selectedDevice.Addresses[1].Address.ToString() : selectedDevice.Addresses[0].Address.ToString();

            addr = addr.Remove(0, 9);

            var selectedDevice2 = temp.GetDestination();
            if (selectedDevice2 == null)
                return;
            string addr2 = selectedDevice2.Addresses.Count == 2 ? selectedDevice2.Addresses[1].Address.ToString() : selectedDevice2.Addresses[0].Address.ToString();

            addr2 = addr2.Remove(0, 9);


            using (PacketCommunicator communicator = selectedDevice.Open(100, // name of the device
                                                                         PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                                                         1000)) // read timeout
            {

                var mac = GetMacFromIp(addr);
                if (mac == "fail")
                {
                    return;
                }
                mac = mac.ToUpper();
                mac = mac.Insert(2, ":");
                mac = mac.Insert(5, ":");
                mac = mac.Insert(8, ":");
                mac = mac.Insert(11, ":");
                mac = mac.Insert(14, ":");

                var source = new MacAddress(mac);

                var macD = GetMacFromIp(addr2);
                if (macD == "fail")
                {
                    return;
                }
                macD = macD.ToUpper();
                macD = macD.Insert(2, ":");
                macD = macD.Insert(5, ":");
                macD = macD.Insert(8, ":");
                macD = macD.Insert(11, ":");
                macD = macD.Insert(14, ":");

                var destination = new MacAddress(macD);

                //try
                //{
                //    destination = new MacAddress(GetMacAddressFromIPAddress.GetMacAddressFromArp("192.168.100.100"));
                //}
                //catch (Exception)
                //{
                //   return;
                //    throw;
                //}

                // Ethernet Layer
                var ethernetLayer = new EthernetLayer
                {
                    Source = source,
                    Destination = destination
                };

                // IPv4 Layer
                var ipV4Layer = new IpV4Layer
                {
                    //Source = new IpV4Address("1.2.3.4"),
                    Source = new IpV4Address(addr),
                    Ttl = 8,
                    // The rest of the important parameters will be set for each packet
                };

                // ICMP Layer
                var icmpLayer = new IcmpEchoLayer();

                // Create the builder that will build our packets
                var builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);

                // Send 100 Pings to different destination with different parameters
                for (int i = 0; i != _pingsent; ++i)
                {
                    // Set IPv4 parameters
                    //ipV4Layer.CurrentDestination = new IpV4Address("2.3.4." + i);

                    ipV4Layer.Destination = new IpV4Address(addr2);
                    ipV4Layer.Identification = (ushort)i;

                    // Set ICMP parameters
                    icmpLayer.SequenceNumber = (ushort)i;
                    icmpLayer.Identifier = (ushort)i;

                    // Build the packet
                    Packet packet = builder.Build(DateTime.Now);

                    // Send down the packet
                    lock (Locker)
                    {
                        communicator.SendPacket(packet);
                        Thread.Sleep(10);
                    }
                }

            }



        }


        private static void Reader(object o)
        {

            int counter = 1;

            var selectedDevice = (PacketDevice)o;
            if (selectedDevice == null)
                return;
            var addr = selectedDevice.Addresses.Count == 2 ? selectedDevice.Addresses[1].Address.ToString() : selectedDevice.Addresses[0].Address.ToString();

            addr = addr.Remove(0, 9);

            string strAddr = addr.Remove(0, 12);
            int numAddr = Convert.ToInt32(strAddr);

            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                //AllocConsole();
                Console.WriteLine(@"Listening on " + selectedDevice.Description + @"...");

                communicator.SetFilter("icmp and dst host " + addr);     // and dst host "+addr);
                // Retrieve the packets
                Packet packet;
                do
                {
                    if (_killThread)
                    {
                        Thread.CurrentThread.Abort();
                        return;
                    }
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:

                            if (packet.Length == 60)
                            {
                                var datt = packet.Ethernet.IpV4.Icmp;
                                uint tt = datt.Variable;
                                tt = tt >> 16;

                                Console.WriteLine(addr + @" = " + counter + @") Var - " + tt);
                                counter++;
                                myState[numAddr - 1] += 1;
                                Thread.Sleep(10);
                                break;
                            }
                            continue;
                        default:
                            throw new InvalidOperationException("The result " + result +
                                                                " shoudl never be reached here");

                    }

                } while (true);

            }

        }

        private void RadioButton1CheckedChanged(object sender, EventArgs e)
        {

            if (radioButton2.Checked) return;
            button3.Enabled = false;

            var query = new SelectQuery("Win32_NetworkAdapter", "NetConnectionStatus=2");
            var search = new ManagementObjectSearcher(query);


            RegistryKey regKey;

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0012", true); //#04
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0014", true); //#08
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0016", true); //#03
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0018", true); //#07
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0020", true); //#02
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0022", true); //#06
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();


            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0024", true); //#01
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0026", true); //#05
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0027", true); //#16
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0030", true); //#12
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0032", true); //#15
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0033", true); //#11
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0036", true); //#14
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0038", true); //#10
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0039", true); //#13
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0042", true); //#09
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "4");
            Registry.LocalMachine.Flush();

            label18.Visible = true;

            for (var ii = 0; ii < myCheckBoxs.Count; ii++)
            {
                myCheckBoxs[ii].Enabled = false;
                radioButton1.Enabled = false;
                radioButton2.Enabled = false;
                myLabel[ii].Text = "";
            }

            foreach (ManagementObject result in search.Get())
            {
                NetworkAdapter adapter = new NetworkAdapter(result);
                if (adapter.AdapterType.Equals("Ethernet 802.3"))
                {
                    adapter.Disable();
                    adapter.Enable();
                }
            }

            for (var ii = 0; ii < myCheckBoxs.Count; ii++)
            {
                myCheckBoxs[ii].Enabled = true;
                radioButton1.Enabled = true;
                radioButton2.Enabled = true;
                myLabel[ii].Text = "";
            }
            label18.Visible = false;
            button3.Enabled = true;
        }


        private void RadioButton2CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton1.Checked) return;
            button3.Enabled = false;
            var query = new SelectQuery("Win32_NetworkAdapter", "NetConnectionStatus=2");
            var search = new ManagementObjectSearcher(query);

            RegistryKey regKey;
            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0012", true); //#04
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0014", true); //#08
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0016", true); //#03
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0018", true); //#07
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0020", true); //#02
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0022", true); //#06
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();


            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0024", true); //#01
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0026", true); //#05
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0027", true); //#16
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0030", true); //#12
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0032", true); //#15
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0033", true); //#11
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0036", true); //#14
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0038", true); //#10
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0039", true); //#13
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            regKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0042", true); //#09
            if (regKey != null) regKey.SetValue("*SpeedDuplex", "2");
            Registry.LocalMachine.Flush();

            label18.Visible = true;
            for (var ii = 0; ii < myCheckBoxs.Count; ii++)
            {
                myCheckBoxs[ii].Enabled = false;
                radioButton1.Enabled = false;
                radioButton2.Enabled = false;
                myLabel[ii].Text = "";
            }

            foreach (ManagementObject result in search.Get())
            {
                NetworkAdapter adapter = new NetworkAdapter(result);
                if (adapter.AdapterType.Equals("Ethernet 802.3"))
                {
                    adapter.Disable();
                    adapter.Enable();
                }
            }

            for (var ii = 0; ii < myCheckBoxs.Count; ii++)
            {
                myCheckBoxs[ii].Enabled = true;
                radioButton1.Enabled = true;
                radioButton2.Enabled = true;
                myLabel[ii].Text = "";
            }
            label18.Visible = false;
            /*
            var temp = new ManagementObject();

            foreach (ManagementObject mo in search.Get())
            {
                temp = mo;
                temp.InvokeMethod("Disable", null);
                temp.InvokeMethod("Enable", null);
            }*/
            button3.Enabled = true;



        }

        private void P215Test_Load(object sender, EventArgs e)
        {

        }

        private void P215Test_FormClosing(object sender, FormClosingEventArgs e)
        {
            Environment.Exit(1);
        }

        private void label16_Click(object sender, EventArgs e)
        {

        }
    }


}
