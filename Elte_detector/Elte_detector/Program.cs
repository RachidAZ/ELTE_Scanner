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
        public static string _YaraEXEPath;
        public static string _YaraRulesPath;
        public static string _QuarantineFolder;
        public static bool _IsFolder = false;

        
        static void Main(string[] args)
        {

            Console.WriteLine("ELTE detector tool - Rachid AZGAOU 2019");
            if (args.Length != 2 )
            {

                ShowHelp();
                return;

            }

            string _param1 = args[0];
            string _param2 = args[1];

            if (_param1.Equals("-d")) 
            {
                _IsFolder = true;

            }
            else if (!_param1.Equals("-f"))
            {
                ShowHelp();
                return;

            }
            
            // read params , if the user wanna scan a folder set the variable isFolder
            // will be used later for showing the dir files in question (progress )
            // call : eltetector.exe .f filename or -d directoryname

          //  Console.WriteLine("Param :  " + args[0]);



            Console.WriteLine("Configuration file reading .. ");
            ReadConfig();



            // Console.WriteLine(System.Reflection.Assembly.GetExecutingAssembly().Location);
            //Console.WriteLine(Directory.GetCurrentDirectory()+ "\\YARAexe\\yara32.exe");

            Console.WriteLine("File(s) scanning started  .. ");
            // scan file 1 , export result , read result , show it in console and move the file to quarantine if detected as malicious

            if (_IsFolder)
            {
                // loop through the files in the folder

            } 
            else
            {
                StartYaraExe(_param2);


            }
            
            Console.WriteLine("File(s) scanning done. ");




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

            _YaraRulesPath = ConfigurationManager.AppSettings.Get("YaraRulesPath");
            _YaraEXEPath = ConfigurationManager.AppSettings.Get("PathYaraEXE");
            _QuarantineFolder = ConfigurationManager.AppSettings.Get("PathQuarantine"); 




        }

        private static void StartYaraExe(string fileName)
        {
            // yara32.exe elteDetector_rules.txt  samples_test/.

           
            string yara32Path = Directory.GetCurrentDirectory() + "\\YARAexe\\yara32.exe";

            // Use ProcessStartInfo class
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.CreateNoWindow = false;
            startInfo.UseShellExecute = false;
            startInfo.FileName = yara32Path;
            //startInfo.WindowStyle = ProcessWindowStyle.Hidden;
             startInfo.Arguments = " \""+ _YaraRulesPath + "\" " + fileName   ;
            //startInfo.Arguments = "-h";
             Console.WriteLine(startInfo.Arguments);

            //"C:\\Users\\razgaou\\OneDrive - Itron\\Documents\\elte\\THESIS PREP\\tool to create\\
            //ELTE_Scanner\\Source\\Repos\\ELTE_Scanner\\Elte_detector\\Elte_detector\\YaraRules\\ ."
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


           



        }
    }
}
