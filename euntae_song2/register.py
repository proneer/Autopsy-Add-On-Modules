# This python autopsy module will export the prefetch files and then call
# the command line version of the prefetch_parser.  A sqlite database that
# contains the prefetch information is created then imported into the extracted
# view section of Autopsy.
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> Davenport [dot] edu]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
import jarray
import inspect
import os
import sys
import subprocess
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils

class ParsePrefetchDbIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Register"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return " Windows register information for Autopsy V3.11"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParsePrefetchDbIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class ParsePrefetchDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParsePrefetchDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    def startUp(self, context):
        self.context = context

        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Prefetch_Parser_Autopsy.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")

    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the prefetch files and the layout.ini file from the /windows/prefetch folder
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "/Windows/System32/config/SYSTEM")
        
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
			
        Temp_Dir = Case.getCurrentCase().getTempDirectory()+"\information_register" #Create Directiroy to save register information
        
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        
        try:
	    	os.mkdir(Temp_Dir)
        except:
            self.log(Level.INFO, "Prefetch Directory already exists " + Temp_Dir)

			
        # Write out each prefetch file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
#

#
        # Example has only a Windows EXE, so bail if we aren't on Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + Case.getCurrentCase().getTempDirectory())
        subprocess.Popen([self.path_to_exe, Temp_Dir, Case.getCurrentCase().getTempDirectory()]).communicate()[0]   
			
        # Set the database to be read to the once created by the prefetch parser program
        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autopsy_PF_DB.db3")
        self.log(Level.INFO, "Path the prefetch database file created ==> " + lclDbPath)
                        
        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
        # Query the contacts table in the database and get all columns. 
        try:
            stmt = dbConn.createStatement()
            resultSet = stmt.executeQuery("Select prefetch_File_Name, actual_File_Name, Number_time_file_run, " +
                                          " Embeded_date_Time_Unix_1, " +
                                          " Embeded_date_Time_Unix_2, " +
                                          " Embeded_date_Time_Unix_3, " +
                                          " Embeded_date_Time_Unix_4, " +
                                          " Embeded_date_Time_Unix_5, " +
                                          " Embeded_date_Time_Unix_6, " +   
                                          " Embeded_date_Time_Unix_7, " +       
                                          " Embeded_date_Time_Unix_8 " +
                                          " from prefetch_file_info ")
        except SQLException as e:
            self.log(Level.INFO, "Error querying database for Prefetch table (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK

        # Cycle through each row and create artifacts
        while resultSet.next():
            try: 
                self.log(Level.INFO, "Result (" + resultSet.getString("Prefetch_File_Name") + ")")
                Prefetch_File_Name  = resultSet.getString("Prefetch_File_Name")
                Actual_File_Name = resultSet.getString("Actual_File_Name")
                Number_Of_Runs = resultSet.getString("Number_Time_File_Run")
                Time_1 = resultSet.getString("Embeded_date_Time_Unix_1")
                Time_2 = resultSet.getString("Embeded_date_Time_Unix_2")
                Time_3 = resultSet.getString("Embeded_date_Time_Unix_3")
                Time_4 = resultSet.getString("Embeded_date_Time_Unix_4")
                Time_5 = resultSet.getString("Embeded_date_Time_Unix_5")
                Time_6 = resultSet.getString("Embeded_date_Time_Unix_6")
                Time_7 = resultSet.getString("Embeded_date_Time_Unix_7")
                Time_8 = resultSet.getString("Embeded_date_Time_Unix_8")
            except SQLException as e:
                self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(dataSource, Prefetch_File_Name)                
            
            for file in files:

                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, Prefetch_File_Name))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, Actual_File_Name))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, Number_Of_Runs))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_1)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_2)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_3)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_END.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_4)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_5)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_6)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_7)))
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_START.getTypeID(), ParsePrefetchDbIngestModuleFactory.moduleName, int(Time_8)))

        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParsePrefetchDbIngestModuleFactory.moduleName, 
            BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN, None))
                
        # Clean up
        stmt.close()
        dbConn.close()
        os.remove(lclDbPath)

			
		#Clean up prefetch directory and files
        for file in files:
            try:
			    os.remove(Temp_Dir + "\\" + file.getName())
            except:
			    self.log(Level.INFO, "removal of prefetch file failed " + Temp_Dir + "\\" + file.getName())
        try:
             os.rmdir(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of prefetch directory failed " + Temp_Dir)
            
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Prefetch Analyzer", " Prefetch Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParsePrefetchDbIngestModuleFactory.moduleName, 
            BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN, None))
        
        return IngestModule.ProcessResult.OK

