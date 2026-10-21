// SPDX-License-Identifier: MPL-2.0
// Executes the real GUI methods with synthetic devices; no DOM or engine claimed.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('gui/default/syncthing/core/syncthingController.js', 'utf8');
const init = source.slice(source.indexOf('        function initShareEditingFolder()'), source.indexOf('        $scope.pendingIsRemoteEncrypted'));
const save = source.slice(source.indexOf('        $scope.saveFolder = function ()'), source.indexOf('        $scope.isFolderTabDisabled'));
let cases = 0;
for (const localPresent of [true, false]) {
    const $scope = {
        myID: 'LOCAL', devices: {REMOTE: {deviceID: 'REMOTE'}},
        currentFolder: {id: 'synthetic', devices: [
            ...(localPresent ? [{deviceID: 'LOCAL', encryptionPassword: 'synthetic-invalid-local'}] : []),
            {deviceID: 'REMOTE', encryptionPassword: 'synthetic-remote-password'},
        ], _editing: 'new-pending', _guiVersioning: {selector: ''}},
        currentSharing: {shared: [], unrelated: [], selected: {}, encryptionPasswords: {}},
        deviceList: () => [{deviceID: 'LOCAL'}, {deviceID: 'REMOTE'}],
        validateXattrFilter: () => {}, internalVersioningEnabled: () => false,
        folders: {}, config: {}, saveConfig: () => ({then: fn => fn()}),
    };
    const context = vm.createContext({$scope, angular: {copy: o => JSON.parse(JSON.stringify(o))}, deviceCompare: () => 0, folderList: Object.values, hideModal: () => {}});
    vm.runInContext(init + save + '\ninitShareEditingFolder();', context);
    assert.equal($scope.currentSharing.encryptionPasswords.LOCAL, undefined);
    assert.equal($scope.currentSharing.encryptionPasswords.REMOTE, 'synthetic-remote-password');
    // Even an unexpected hidden value injected after modal initialization is discarded.
    $scope.currentSharing.encryptionPasswords.LOCAL = 'synthetic-unexpected-hidden';
    $scope.saveFolder();
    const devices = $scope.config.folders[0].devices;
    assert.equal(devices.length, 2);
    assert.equal(devices.find(d => d.deviceID === 'LOCAL').encryptionPassword, '');
    assert.equal(devices.find(d => d.deviceID === 'REMOTE').encryptionPassword, 'synthetic-remote-password');
    cases++;
}
console.log(JSON.stringify({status: 'PASS', cases, assertions: cases * 5, scope: 'actual GUI methods with synthetic fixtures, not Windows UI reception'}));
