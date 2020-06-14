from core import plugin, model

class _inga(plugin._plugin):
    version = 0.2

    def install(self):
        # Register models
        model.registerModel("ingaIPDiscover","_ingaIPDiscover","_trigger","plugins.inga.models.trigger")
        model.registerModel("inga","_inga","_document","plugins.inga.models.inga")
        model.registerModel("ingaWebScreenShot","_ingaWebScreenShot","_action","plugins.inga.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("ingaIPDiscover","_ingaIPDiscover","_trigger","plugins.inga.models.trigger")
        model.deregisterModel("inga","_inga","_document","plugins.inga.models.inga")
        model.deregisterModel("ingaWebScreenShot","_ingaWebScreenShot","_action","plugins.inga.models.action")
        return True
    