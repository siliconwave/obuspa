#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/stat.h>

#define FIRMWARE_PATH "/tmp/fw_update.bin"

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t write_data(void *contents, size_t size, size_t nmemb, void *userp) {
  FILE *fp = (FILE *)userp;
  return fwrite(contents, size, nmemb, fp);
}

bool download_firmware(const char *url) {
  CURL *curl = curl_easy_init();
  if (!curl) return false;

  FILE *fp = fopen(FIRMWARE_PATH, "wb");
  if (!fp) return false;

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
  CURLcode res = curl_easy_perform(curl);

  fclose(fp);
  curl_easy_cleanup(curl);
  return res == CURLE_OK;
}

int apply_firmware() {
  // Simulated: Replace with reboot or update logic
  printf("Applying firmware from: %s\n", FIRMWARE_PATH);

  // You could validate the file, then copy it, flash it, etc.
  // Or trigger your own update shell script here
  return 0;
}
