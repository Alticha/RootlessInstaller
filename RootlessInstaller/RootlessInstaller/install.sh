#!/bin/sh
# RootlessInstallerInstaller

# Kill application
killall -9 RootlessInstaller
# Copy application
ROOTLESSINSTALLER=$0
ROOTLESSINSTALLER=${ROOTLESSINSTALLER%/*}
cp -R $ROOTLESSINSTALLER /var/Apps/RootlessInstaller.app
rm -rf ${ROOTLESSINSTALLER%/*}
ROOTLESSINSTALLER="/var/Apps/RootlessInstaller.app"
# Install application
jtool --sign --inplace --ent "$ROOTLESSINSTALLER/ent.xml" "$ROOTLESSINSTALLER/RootlessInstaller"
uicache
ROOTLESSINSTALLER=$(find /var/containers/Bundle/Application | grep RootlessInstaller.app/RootlessInstaller)
inject $ROOTLESSINSTALLER
chown root $ROOTLESSINSTALLER
chmod 6755 $ROOTLESSINSTALLER
# Finished
echo "Installed RootlessInstaller!"
echo "Every time you jailbreak, you'll have to run the following command:"
echo "inject $ROOTLESSINSTALLER"
echo "to prevent the application from crashing until rootlessJB is updated with a fix for this bug."
echo "Enjoy! :-)"
