import jarray
import inspect
from java.lang import System
from java.io import File
from java.util.logging import Level
from java.sql  import DriverManager, SQLException
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JButton
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JCheckBox
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
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
from java.lang import IllegalArgumentException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils

class HangulFinderModuleFactory(IngestModuleFactoryAdapter) :
    moduleName = "HangulFinder"
    def getModuleDisplayName(self) :
        return self.moduleName
    def getModuleDescription(self) :
        return "Find Correct Hangul File (.hwp)"
    def getModuleVersionNumber(self) :
        return "1.0"
    def isFileIngestModuleFactory(self) :
        return True
    def createFileIngestModule(self, ingestOptions) :
        return HangulFinderIngestModule()

class HangulFinderIngestModule(FileIngestModule) :

    _logger = Logger.getLogger(HangulFinderModuleFactory.moduleName)
    
    def log(self, level, msg) :
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    
    def __init__(self) :
        self.context = None

    def startUp(self, context) :
        self.filesFound = 0
        pass

    def process(self, file) :
        if file.isFile() == False :
            pass

        elif file.getName().lower().endswith(".hwp") :
            self.log(Level.INFO, "Found a hwp Extension FILE : " + file.getName())
            self.filesFound += 1

            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                  HangulFinderModuleFactory.moduleName, "Hangul Extension")
            art.addAttribute(att)

            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(HangulFinderModuleFactory.moduleName,
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        inputStream = ReadContentInputStream(file)
        buffer = jarray.zeros(8, "b")

        if inputStream.read(buffer) != -1 :
            if buffer[:8].tostring() == "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" : #Hangul Header
                self.log(Level.INFO, "Found a hwp Header FILE : " + file.getName())
                self.filesFound += 1

                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                      HangulFinderModuleFactory.moduleName, "Hangul Header")
                art.addAttribute(att)

                IngestServices.getInstance().fireModuleDataEvent(
                    ModuleDataEvent(HangulFinderModuleFactory.moduleName,
                        BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        return IngestModule.ProcessResult.OK

    def shutDown(self) :
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, HangulFinderModuleFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)