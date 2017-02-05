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

# This will work in 4.+ and beyond
# from org.sleuthkit.autopsy.casemodule.services import Blackboard

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.

class FileMarkerIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Makr_File"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Mark Some Specific Files(Artifacts) to Analysis Image file"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    #def isFileIngestModuleFactory(self):
    #    return True
    
    # can return null if isFileIngestModuleFactory returns false
    #def createFileIngestModule(self, ingestOptions):
    #    return FindLogFilesIngestModule()

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return FileMarkerIngestModule()

# File-level ingest module.  One gets created per thread.
class FileMarkerIngestModule(FileIngestModule):

    _logger = Logger.getLogger(FileMarkerIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")        
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.3/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    def process(self, file):
        
        # This will work in 4.+ and beyond
        # Use blackboard class to index blackboard artifacts for keyword search
        # blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or 
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or 
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
    
        if (file.getName() == "$MFT" or file.getName() == "$LogFile" or file.getName() == "$UsnJrnl:$J"):
            
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                  FileMarkerIngestModuleFactory.moduleName, "File System")
            art.addAttribute(att)
  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkerIngestModuleFactory.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        elif (file.getNameExtension() == "evtx"):
            
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                  FileMarkerIngestModuleFactory.moduleName, "Event Logs")
            art.addAttribute(att)
  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkerIngestModuleFactory.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        elif (file.getName() == "pagefile.sys" or file.getName() == "hiberfil.sys"):
            
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                  FileMarkerIngestModuleFactory.moduleName, "Page file")
            art.addAttribute(att)
  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkerIngestModuleFactory.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        elif (file.getNameExtension() == "pf"):
            
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                  FileMarkerIngestModuleFactory.moduleName, "Prefetch")
            art.addAttribute(att)
  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkerIngestModuleFactory.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        elif (file.getName() == "SYSTEM" or file.getName() == "SECURITY" or file.getName() == "SOFTWARE" or file.getName() == "SAM" or file.getName() == "NTUSER.DAT" or file.getName() == "UsrClass.dat" or file.getName() == "RecentFileCache.bcf" or file.getName() == "Amcache.hve"):
            
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), 
                  FileMarkerIngestModuleFactory.moduleName, "Important Registry")
            art.addAttribute(att)
  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkerIngestModuleFactory.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));
        else:
            pass

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here. 
    def shutDown(self):
        None
