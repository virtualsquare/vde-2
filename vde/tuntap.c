/* Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 * This file is part of the original uml_switch code
 * Modified 2003 Renzo Davoli
 */

#include <config.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <port.h>
#include <switch.h>

void send_tap(int fd, void *packet, int len, void *unused)
{
  int n;

  n = write(fd, packet, len);
  if(n != len){
    if(errno != EAGAIN) printlog(LOG_WARNING,"send_tap %s",strerror(errno));
  }
}

int open_tap(char *dev)
{
  struct ifreq ifr;
  int fd;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0){
    printlog(LOG_ERR,"Failed to open /dev/net/tun %s",strerror(errno));
    return(-1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
  /*printf("dev=\"%s\", ifr.ifr_name=\"%s\"\n", ifr.ifr_name, dev);*/
  if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0){
    printlog(LOG_ERR,"TUNSETIFF failed %s",strerror(errno));
    close(fd);
    return(-1);
  }
  return(fd);
}
