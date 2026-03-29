#pragma once

#include <QObject>
#include "interface.h"
#include "logos_provider_object.h"
#include "accounts_module_qt_glue.h"

class AccountsModuleLoader : public QObject, public PluginInterface, public LogosProviderPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID LogosProviderPlugin_iid FILE "metadata.json")
    Q_INTERFACES(PluginInterface LogosProviderPlugin)

public:
    QString name() const override { return "accounts_module"; }
    QString version() const override { return "1.0.0"; }
    LogosProviderObject* createProviderObject() override {
        return new AccountsModuleProviderObject();
    }
};
