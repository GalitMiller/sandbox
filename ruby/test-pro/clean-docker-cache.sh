#!/bin/bash

# Clean docker cache when it is full to free some space.
# Only untagged images will be deleted. Tagged images (downloaded
# from remote repository or tagged localy) will be left intact,
# but intermediate containers, used to speed up builds, will be deleted.

echo "Removing stopped containers..."
docker rm $(docker ps -a -q)

echo "Removing unused untagged containers..."
docker rmi $(docker images -q --filter "dangling=true")

echo "OK"
