using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;


// to add
// detect zp files , unzip and scan , report as malicious if protected with password
// detect as malicious win services win api startservice ..
// big resource is malicious
// detect html files , injected with malicious vb script (write files and invoke external programs ..)


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


            SetGlobalExceptionHandler();
            Console.WriteLine("ELTE detector tool - Rachid AZGAOU 2019");
            Console.WriteLine("");
            if (args.Length != 2 )
            {

                ShowHelp();
                return;

            }

            string _param1 = args[0];
            string _param2 = args[1];


            // FOR TESTING ------------------------------

            //_param1 = "-d";
           // _param2 = "C:\\Users\\razgaou\\OneDrive - Itron\\Documents\\elte\\THESIS PREP\\tool to create\\ELTE_Scanner\\Source\\Repos\\ELTE_Scanner\\Elte_detector\\Elte_detector\\bin\\Debug";
            //  ----------------------------------------


            if (_param1.Equals("-d")) 
            {
                _IsFolder = true;

            }
            else if (!_param1.Equals("-f"))
            {
                ShowHelp();
                return;

            }


           





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

                if (!Directory.Exists(_param2))
                {

                    Console.WriteLine("Directory not found ! ");
                    Console.ReadKey();
                    return;

                }
                else
                {
                    Console.WriteLine("DateTime Start : " + DateTime.Now.ToString("dd/MM/yyyy hh:mm tt"));

                    List<String> files = new List<string> ( Directory.EnumerateFiles(_param2));
                    Console.WriteLine(String.Format("Analyzing the files in the directory  [{0}] .. ", _param2));
                    foreach (var f in files)
                    {

                        // Console.WriteLine(f);
                       

                        StartYaraExe(f);
                        PostScan(f);
                        


                    }


                    Console.WriteLine("DateTime End : " + DateTime.Now.ToString("dd/MM/yyyy hh:mm tt"));


                }

            } 
            else
            {

                if (!File.Exists(_param2))
                {

                    Console.WriteLine(String.Format("File [{0}] not found ! ",_param2));
                    Console.ReadKey();
                    return;

                }
                else
                {

                    Console.WriteLine(String.Format("Analyzing the file [{0}] .. ", _param2));

                    Console.WriteLine("DateTime Start : "+ DateTime.Now.ToString("dd/MM/yyyy hh:mm tt"));

                    StartYaraExe(_param2);
                    PostScan(_param2);

                    Console.WriteLine("DateTime End : " + DateTime.Now.ToString("dd/MM/yyyy hh:mm tt"));

                }

            }
            




            Console.WriteLine("File(s) scanning done. ");

            


            Console.ReadLine();




        }

        private static void PostScan(string fileName)
        {
            // read the res.elte file , print result in the console , move the file to Quarantine if res.elte is empty


            try
            {


          

            string[] res = File.ReadAllLines("res.elte");
            Console.Write(String.Format("Scanning result for [{0}] : " , fileName));
            foreach (var v in res )
            {

                Console.WriteLine(v);

            }


                // move the file to quarantine with the extension .mal , to avoid its execution accidentally

                if (res.Length>0)
            {
                String des = _QuarantineFolder +  Path.GetFileName(fileName) + ".mal";
                if (File.Exists(des)) des +=  DateTime.UtcNow.ToString().Replace("/","-").Replace(" ","").Replace(':','_')+".mal";

                File.Move(fileName, des);
                Console.WriteLine("[Warning] This file has been moved to the Quarantine!");

            } 
            else
            {
                Console.WriteLine("The file is Clean!");

            }


            }
            catch(Exception ex)
            {

                Console.WriteLine("Moving the file to the Quarantine error :  " + ex.Message);

            }


        }

        private static void SetGlobalExceptionHandler()
        {

            AppDomain currentDomaine = AppDomain.CurrentDomain;
            currentDomaine.UnhandledException += new UnhandledExceptionEventHandler(Handler);
           
        }

        private static void Handler(object sender, UnhandledExceptionEventArgs e)
        {


            Console.WriteLine("Unhandled exception : " + ((Exception) e.ExceptionObject).Message);

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
            
            string yara32Path = Directory.GetCurrentDirectory() + "\\YARAexe\\yara32.exe";

            
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.WorkingDirectory = Directory.GetCurrentDirectory();
            startInfo.CreateNoWindow = false;
            startInfo.UseShellExecute = false;
            startInfo.FileName = "cmd";
            //startInfo.WindowStyle = ProcessWindowStyle.Hidden;
             startInfo.Arguments = "/C YARAexe\\yara32.exe \"" + _YaraRulesPath + "\" \"" + fileName  + "\" >res.elte"  ;
          
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
