#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>

#include "mctp.h"

static const mctp_eid_t DEFAULT_EID = 8;
static const size_t DEFAULT_SIZE = 1;
static const int DEFAULT_SECONDS_INTERVAL = 10;
static const int MAX_SAMPLES = 20;

static int mctp_bench_recv() {
  struct sockaddr_mctp addr;
  ssize_t len = 0;
  ssize_t curr_len;
  int rc, sd;

  struct timespec start_time, current_time, sample_time;
  double throughput_samples[MAX_SAMPLES];
  int sample_count = 0;

  sd = socket(AF_MCTP, SOCK_DGRAM, 0);
  if (sd < 0)
    err(EXIT_FAILURE, "socket");

  memset(&addr, 0, sizeof(addr));
  addr.smctp_family = AF_MCTP;
  addr.smctp_network = MCTP_NET_ANY;
  addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
  addr.smctp_type = 1;
  addr.smctp_tag = MCTP_TAG_OWNER;

  rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc)
    err(EXIT_FAILURE, "bind");

  // Get the start time and initialize sampling time
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  sample_time = start_time;

  while (1) {
    curr_len = recvfrom(sd, NULL, 0, MSG_TRUNC, NULL, 0);

    if (curr_len < 0) {
      warn("recvfrom(MSG_TRUNC)");
      continue;
    }

    len += curr_len;

    clock_gettime(CLOCK_MONOTONIC, &current_time);

    double elapsed_sample_time =
        (current_time.tv_sec - sample_time.tv_sec) +
        (current_time.tv_nsec - sample_time.tv_nsec) / 1e9;
    // Store the current sample througput into array
    if (elapsed_sample_time >= 1.0) {
      double throughput = len / elapsed_sample_time;

      if (sample_count < MAX_SAMPLES) {
        throughput_samples[sample_count++] = throughput;
      }

      len = 0;
      sample_time = current_time;
    }

    double elapsed_time = (current_time.tv_sec - start_time.tv_sec) +
                          (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
    // Print out the throughputs
    if (elapsed_time >= DEFAULT_SECONDS_INTERVAL) {
      printf("Throughput samples over the last %d seconds:\n",
             DEFAULT_SECONDS_INTERVAL);
      for (int i = 0; i < sample_count; i++) {
        printf("Sample %d: %.2f bytes/second\n", i + 1, throughput_samples[i]);
      }

      sample_count = 0;
      clock_gettime(CLOCK_MONOTONIC, &start_time);
    }
  }

  return 0;
}

static int mctp_bench_send(mctp_eid_t eid, size_t len) {
  struct sockaddr_mctp addr;
  unsigned char *buf;
  socklen_t addrlen;
  int rc, sd;

  struct mctp_ioc_tag_ctl ctl = {
      .peer_addr = eid,
  };

  sd = socket(AF_MCTP, SOCK_DGRAM, 0);
  if (sd < 0) {
    err(EXIT_FAILURE, "socket");
  }

  memset(&addr, 0x0, sizeof(addr));
  addr.smctp_family = AF_MCTP;
  addr.smctp_network = MCTP_NET_ANY;
  addr.smctp_addr.s_addr = eid;
  addr.smctp_type = 1;
  printf("sending to edi:%d, type %d\n", eid, addr.smctp_type);

  buf = malloc(len);
  if (!buf) {
    err(EXIT_FAILURE, "malloc");
  }
  for (size_t i = 0; i < len; i++) {
    buf[i] = i & 0xff;
  }

  rc = ioctl(sd, SIOCMCTPALLOCTAG, &ctl);

  if (rc) {
    err(EXIT_FAILURE, "Alloc tag failed");
  }

  while (1) {
    addr.smctp_tag = ctl.tag;
    addrlen = sizeof(addr);
    rc = sendto(sd, buf, len, 0, (struct sockaddr *)&addr, addrlen);

    if (rc != (int)len) {
      err(EXIT_FAILURE, "sendto(%zd)", len);
    }
  }

  return 0;
}

static void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  mctp-bench send --size=SIZE eid <EID>\n");
  fprintf(stderr, "  mctp-bench recv\n");
  fprintf(stderr, "  Defaults: eid=%d, size=%zd\n", DEFAULT_EID, DEFAULT_SIZE);
}

int main(int argc, char **argv) {
  mctp_eid_t eid = DEFAULT_EID;
  size_t size = DEFAULT_SIZE;
  char *endptr, *optname, *optval;
  unsigned int tmp_int;
  int command = 0;

  if (argc < 2) {
    fprintf(stderr, "Error: Missing command\n");
    usage();
    return 255;
  }

  if (strcmp(argv[1], "send") == 0) {
    command = 1;
  } else if (strcmp(argv[1], "recv") == 0) {
    command = 2;
  } else {
    fprintf(stderr, "Error: Unknown command: %s\n", argv[1]);
    usage();
    return 255;
  }

  switch (command) {
  case 1: // send
    if (argc > 5) {
      fprintf(stderr, "Error: Too many argument for send\n");
      usage();
      return 255;
    }

    for (int i = 2; i < argc; i++) {
      optname = argv[i];

      if (strcmp(optname, "eid") == 0) {
        optval = argv[i + 1];
        tmp_int = strtoul(optval, &endptr, 0);

        if (tmp_int > 0xff || *endptr != '\0') {
          errx(EXIT_FAILURE, "BAD eid: %s", optval);
        }
        eid = tmp_int;
        i++;
      } else if (strncmp(optname, "--size=", 7) == 0) {
        optval = argv[i] + 7;
        size_t tmp = strtoul(optval, &endptr, 0);

        if (*endptr != '\0') {
          errx(EXIT_FAILURE, "invalid size value %s", optval);
        }

        size = tmp;
      } else {
        fprintf(stderr, "Error: Unknown argument: %s\n", optname);
        usage();
        return 255;
      }
    }

    return mctp_bench_send(eid, size);

  case 2: // recv
    if (argc > 2) {
      fprintf(stderr, "Error: recv does not take any arguments\n");
      usage();
      return 255;
    }

    return mctp_bench_recv();

  default:
    fprintf(stderr, "Error: Invalid command\n");
    usage();
    return 255;
  }

  return EXIT_FAILURE;
}