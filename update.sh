git pull
cd resources/kenzer-bin/
git pull
sudo cp * /usr/bin/
cd ../kenzer-templates
git pull
sudo systemctl restart kenzer.service
