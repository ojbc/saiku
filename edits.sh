#!/bin/bash

# Remove saiku logo
sed -i '269d' saiku-ui/index.html

# don't show dashboard page on startup
sed -i "285d" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "285iif (false) {" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "257d" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "257iif (false) {" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "231d" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "231iif (false) {" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "170d" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "170iif (false) {" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "108d" saiku-ui/js/saiku/models/SessionWorkspace.js
sed -i "108iif (false) {" saiku-ui/js/saiku/models/SessionWorkspace.js

# Disable license prompt header
sed -i "22d" saiku-ui/js/saiku/Settings.js
sed -i '22iLICENSE: {licenseType: "open source"},' saiku-ui/js/saiku/Settings.js
