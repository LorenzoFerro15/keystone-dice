#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <stddef.h>
#include <cerrno>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <stdarg.h>

#define BOOST_STRINGIZE(X) BOOST_DO_STRINGIZE(X)
#define BOOST_DO_STRINGIZE(X) #X

#define KEYSTONE_DEV_PATH "/dev/keystone_enclave"

#define MSG(str) "[Keystone SDK] " __FILE__ ":" BOOST_STRINGIZE(__LINE__) " : " str
#define ERROR(str, ...) fprintf(stderr, MSG(str) "\n", ##__VA_ARGS__)
#define PERROR(str) perror(MSG(str))

typedef enum {
  KEYSTONE_ERROR=-1,
  KEYSTONE_SUCCESS,
  KEYSTONE_NOT_IMPLEMENTED,
} keystone_status_t;

class Keystone
{
private:
  int eid;
  int fd;
public:
  Keystone();
  ~Keystone();
  keystone_status_t init(void* ptr, size_t size);
  keystone_status_t destroy();
  keystone_status_t copyFromEnclave(void* ptr, size_t size);
  keystone_status_t copyToEnclave(void* ptr, size_t size);
  keystone_status_t run(void* ptr);
  keystone_status_t initRuntime(const char* filename);
};

#endif
