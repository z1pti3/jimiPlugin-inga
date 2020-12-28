from core import plugin, model

class _inga(plugin._plugin):
    version = 0.6

    def install(self):
        # Register models
        model.registerModel("ingaIPDiscover","_ingaIPDiscover","_trigger","plugins.inga.models.trigger")
        model.registerModel("inga","_inga","_document","plugins.inga.models.inga")
        model.registerModel("ingaWebScreenShot","_ingaWebScreenShot","_action","plugins.inga.models.action")
        model.registerModel("ingaPortScan","_ingaPortScan","_action","plugins.inga.models.action")
        model.registerModel("ingaWebServerDetect","_ingaWebServerDetect","_action","plugins.inga.models.action")
        model.registerModel("ingaIPDiscoverAction","_ingaIPDiscoverAction","_action","plugins.inga.models.action")
        model.registerModel("ingaGetScanUp","_ingaGetScanUp","_trigger","plugins.inga.models.trigger")
        model.registerModel("ingaGetScanUpAction","_ingaGetScanUpAction","_action","plugins.inga.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("ingaIPDiscover","_ingaIPDiscover","_trigger","plugins.inga.models.trigger")
        model.deregisterModel("inga","_inga","_document","plugins.inga.models.inga")
        model.deregisterModel("ingaWebScreenShot","_ingaWebScreenShot","_action","plugins.inga.models.action")
        model.deregisterModel("ingaPortScan","_ingaPortScan","_action","plugins.inga.models.action")
        model.deregisterModel("ingaWebServerDetect","_ingaWebServerDetect","_action","plugins.inga.models.action")
        model.deregisterModel("ingaGetScanUp","_ingaGetScanUp","_trigger","plugins.inga.models.trigger")
        model.deregisterModel("ingaGetScanUpAction","_ingaGetScanUpAction","_action","plugins.inga.models.action")
        return True
    
    def upgrade(self,LatestPluginVersion):
        if self.version < 0.6:
            model.registerModel("ingaGetScanUp","_ingaGetScanUp","_trigger","plugins.inga.models.trigger")
            model.registerModel("ingaGetScanUpAction","_ingaGetScanUpAction","_action","plugins.inga.models.action")
        if self.version < 0.5:
            model.registerModel("ingaIPDiscoverAction","_ingaIPDiscoverAction","_action","plugins.inga.models.action")
        if self.version < 0.4:
            model.registerModel("ingaWebServerDetect","_ingaWebServerDetect","_action","plugins.inga.models.action")
        if self.version < 0.3:
            model.registerModel("ingaPortScan","_ingaPortScan","_action","plugins.inga.models.action")
