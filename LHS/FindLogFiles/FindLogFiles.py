# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# Simple file-level ingest module for Autopsy.
# Used as part of Python tutorials from Basis Technology - July 2015
# http://www.basistech.com/python-autopsy-module-tutorial-1-the-file-ingest-module/
#
# Looks for big files that are a multiple of 4096 and makes artifacts

import re

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
# This will work in 4.0.1 and beyond
# from org.sleuthkit.autopsy.casemodule.services import Blackboard

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
class FindLogFilesIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Log File Finder"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "All Program's Log File Finder - LHS"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    #def isFileIngestModuleFactory(self):
    #    return True
    
    # can return null if isFileIngestModuleFactory returns false
    #def createFileIngestModule(self, ingestOptions):
    #    return FindLogFilesIngestModule()
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return FindLogFilesIngestModule()

# File-level ingest module.  One gets created per thread.
class FindLogFilesIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(FindLogFilesIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.filesFound = 0
        self.context = context
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.3/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # This will work in 4.0.1 and beyond
        # Use blackboard class to index blackboard artifacts for keyword search
        # blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Find files named *.log, regardless of parent path
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.log")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
        for file in files:
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
            FindLogFilesIngestModuleFactory.moduleName, "Log Files")
            art.addAttribute(att)

            ############# This is finding datetime information ###################
            # Step 1: Save file temporary and open it
            tmpPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
            ContentUtils.writeToFile(file, File(tmpPath))
            fdata = open(tmpPath, "rb")
            result = open('C:\\User\\LHS\\Desktop\\result.txt', 'wb+')
            # filename check
            date = re.findall('([\d]{4}.?[\d]{2}.?[\d]{2}[T|_|-][\d]*)', file.getName())

            # Case 1: date is in filename
            if(date != []):
                dnt = re.findall('([T|_|-][\d]*)', date[0])
                # Case 1-1: time is also in filename
                if(dnt != []):
                    result.write(file.getName()+' >> '+date[0]+' '+dnt[0]+'\n')
                # Case 1-2: time is not in filename -- find time in file data
                else:
                    line = fdata.readline()
                    timefind = []
                    while line != "":
                        timefind = re.findall('([\d]{2}[:][\d]{2}[:][\d]{2})',line)
                        if timefind != []:
                            result.write(file.getName()+' >> '+date[0]+' '+timefind[0]+'\n')
                            break
                        line = fdata.readline()
            # Case 2: date is not in filename -- find datetime in file data
            else:
                line = fdata.readline()
                dtfind = []
                while line != "":
                    dtfind = re.findall('([\d]{4}.?[\d]{2}.?[\d]{2}[T|_|-][\d]*)',line)
                    if dtfind != []:
                        result.write(file.getName()+' >> '+date[0]+' '+dtfind[0]+'\n')
                        break
                    line = fdata.readline()
            fdata.close()
            result.close()


            # This will work in 4.0.1 and beyond
            #try:
            #    # index the artifact for keyword search
            #    blackboard.indexArtifact(art)
            #except Blackboard.BlackboardException as e:
            #    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
            
            # Fire an event to notify the UI and others that there is a new artifact  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FindLogFilesIngestModuleFactory.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Find Log Files", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK
    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        None
