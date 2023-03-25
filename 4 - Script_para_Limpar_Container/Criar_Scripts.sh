cat >'/bin/limparfull' <<EOT
docker stop $(docker ps -a -q) && 
docker rm $(docker ps -a -q) && 
docker rmi $(docker images -q) && 
docker system prune --all --force && 
docker system prune -a && 
docker volume ls -f dangling=true && 
docker volume prune &&
docker image prune --filter="label=deprecated"
EOT

chmod 777 /bin/limparfull

cat >'/bin/limparparcial' <<EOT
docker system prune && 
docker system prune -a && 
docker volume ls -f dangling=true && 
docker volume prune
EOT

chmod 777 /bin/limparparcial