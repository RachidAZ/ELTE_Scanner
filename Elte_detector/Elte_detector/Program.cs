using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Diagnostics;
using System.IO;

namespace Elte_detector
{
    class Program
    {

        // to be read during runtime from the app.config
        public static string PathYaraEXE;
        public static string YaraRulesPath;


        
        static void Main(string[] args)
        {

            Console.WriteLine("ELTE detector tool - Rachid AZGAOU 2019");
            if (args.Length != 2 )
            {

                ShowHelp();
                return;

            }


           
            
            Console.WriteLine("Configuration file reading .. ");
            ReadConfig();



            // Console.WriteLine(System.Reflection.Assembly.GetExecutingAssembly().Location);
            //Console.WriteLine(Directory.GetCurrentDirectory()+ "\\YARAexe\\yara32.exe");

            Console.WriteLine("File(s) scanning  .. ");
            StartYaraExe();




          
            Console.ReadLine();




        }

        private static void ShowHelp()
        {

            // Usage : ELTEdet -f malware.exe
            //         Eltedet -d desktop/samples

            Console.WriteLine("ELTE detector , Wrong Params");
            Console.WriteLine("Usage : ELTEdet -f FILENAME");
            Console.WriteLine("        ELTEdet -d DIRECTORY");
            Console.ReadKey();



        }

        private static void ReadConfig()
        {

            //  Console.WriteLine(ConfigurationManager.AppSettings.Get("YaraRulesPath"));

            YaraRulesPath = ConfigurationManager.AppSettings.Get("YaraRulesPath");
            PathYaraEXE = ConfigurationManager.AppSettings.Get("PathYaraEXE");





        }

        private static void StartYaraExe()
        {


            const string ex1 = "C:\\";
            const string ex2 = "C:\\Dir";
            string yara32Path = Directory.GetCurrentDirectory() + "\\YARAexe\\yara32.exe";

            // Use ProcessStartInfo class
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.CreateNoWindow = false;
            startInfo.UseShellExecute = false;
            startInfo.FileName = yara32Path;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            //startInfo.Arguments = "-f j -o \"" + ex1 + "\" -z 1.0 -s y " + ex2;

            try
            {
                // Start the process with the info we specified.
                // Call WaitForExit and then the using statement will close.
                using (Process exeProcess = Process.Start(startInfo))
                {
                    exeProcess.WaitForExit();
                }
            }
            catch(Exception ex)
            {
                // Log error.
                Console.WriteLine("Error while executing yara32.exe : " + ex.Message);
            }


            Console.ReadLine();



        }
    }
}
