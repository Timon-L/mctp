#define _XOPEN_SOURCE 700
#include <bits/time.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "mctp.h"

volatile sig_atomic_t running = 1;

struct msg_header {
        uint8_t op_flag;
        uint32_t seq_no;
};

struct mctp_stats {
        float throughput;
        double elapsed_time;
        unsigned long packets_dropped;
        unsigned long packets_count;
        unsigned long invalid_payloads;
        ssize_t total_received_len;
        ssize_t curr_packet_len;
        uint32_t prev_seq_no;
};

static const mctp_eid_t DEFAULT_EID = 8;
static const int DEFAULT_SECONDS_INTERVAL = 10;
static const size_t MSG_HEADER_SIZE = sizeof(struct msg_header);
static const uint8_t SEND_TERMINATE_SIG = 0;
static const uint8_t SEND_RUNNING_SIG = 1;

static bool valid_payload(unsigned char *buf, size_t buflen)
{
        for (size_t i = MSG_HEADER_SIZE + 1; i < buflen; i++) {
                if (buf[i] != (unsigned char)(buf[i - 1] + 1))
                        return false;
        }
        return true;
}

static void handler(int signum)
{
        printf("**caught signal %d, send is terminating**\n", signum);
        running = 0;
}

static uint32_t get_diff(uint32_t curr, uint32_t prev)
{
        if (prev < curr)
                return curr - prev;
        return UINT32_MAX - prev + curr + 1;
}

static int mctp_bench_recv()
{
        struct timespec start_time, current_time;
        struct sockaddr_mctp addr;
        socklen_t addrlen;
        size_t buflen;
        uint32_t seq_diff;
        struct msg_header *hdr;
        struct mctp_stats mctp_stats = {0};
        unsigned char *buf;
        int rc, sd;
        volatile bool started_recv_flag = false;

        sd = socket(AF_MCTP, SOCK_DGRAM, 0);
        if (sd < 0)
                err(EXIT_FAILURE, "recv: socket");

        memset(&addr, 0, sizeof(addr));
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = MCTP_NET_ANY;
        addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
        addr.smctp_type = 1;
        addr.smctp_tag = MCTP_TAG_OWNER;

        buflen = 0;
        buf = NULL;

        rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
        if (rc) {
                close(sd);
                err(EXIT_FAILURE, "recv: bind failed");
        }

        printf("recv: waiting for packets\n");
        while (1) {
                int time_to_print;
                struct pollfd pollfd[1];
                pollfd[0].fd = sd;
                pollfd[0].events = POLLIN;
                // Calculate the time to next print.
                if (started_recv_flag) {
                        clock_gettime(CLOCK_MONOTONIC, &current_time);
                        unsigned int current_sec = current_time.tv_sec;
                        unsigned int start_sec = start_time.tv_sec;
                        int time_to_print_sec = (DEFAULT_SECONDS_INTERVAL) -
                                                (current_sec - start_sec);
                        time_to_print =
                            (time_to_print > 0) ? time_to_print_sec * 1000 : 0;
                } else {
                        time_to_print = -1;
                }

                rc = poll(pollfd, 1, time_to_print);
                if (rc < 0) {
                        warn("recv: poll failed");
                        break;
                }

                if (pollfd[0].revents & POLLIN) {
                        mctp_stats.curr_packet_len = recvfrom(
                            sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
                        if (mctp_stats.curr_packet_len < 0) {
                                warn("recv: recvfrom(MSG_PEEK");
                                continue;
                        }

                        if ((size_t)mctp_stats.curr_packet_len > buflen) {
                                buflen = mctp_stats.curr_packet_len;
                                unsigned char *new_buf = realloc(buf, buflen);
                                if (!new_buf) {
                                        fprintf(
                                            stderr,
                                            "recv: Failed to allocate memory "
                                            "for buffer of size %zd\n",
                                            buflen);
                                        free(buf);
                                        close(sd);
                                        err(EXIT_FAILURE, "recv: realloc");
                                }
                                buf = new_buf;
                        }

                        addrlen = sizeof(addr);
                        mctp_stats.curr_packet_len =
                            recvfrom(sd, buf, buflen, 0,
                                     (struct sockaddr *)&addr, &addrlen);
                        if (mctp_stats.curr_packet_len < 0) {
                                warn("recv: recvfrom");
                                continue;
                        }

                        if (addrlen != sizeof(addr)) {
                                warnx("recv: unknown addr len:%d, exp:%zd",
                                      addrlen, sizeof(addr));
                                continue;
                        }

                        hdr = (struct msg_header *)buf;
                        if (hdr->op_flag == SEND_TERMINATE_SIG) {
                                printf("recv: sender terminating signal "
                                       "received\n");

                                addr.smctp_tag &= ~MCTP_TAG_OWNER;

                                rc = sendto(sd, buf, buflen, 0,
                                            (struct sockaddr *)&addr,
                                            sizeof(addr));
                                if (rc != (int)mctp_stats.curr_packet_len) {
                                        warn("recv: sendto");
                                }
                                printf("recv: ACK sent\n");
                                break;
                        }

                        mctp_stats.total_received_len +=
                            mctp_stats.curr_packet_len;
                        mctp_stats.packets_count++;
                        if (!valid_payload(buf, mctp_stats.curr_packet_len))
                                mctp_stats.invalid_payloads++;

                        if (!started_recv_flag) {
                                printf("recv: first packet received\n");
                                started_recv_flag = true;
                                clock_gettime(CLOCK_MONOTONIC, &start_time);
                                continue;
                        }
                        seq_diff =
                            get_diff(hdr->seq_no, mctp_stats.prev_seq_no);
                        if (seq_diff > 1)
                                mctp_stats.packets_dropped += seq_diff;
                        mctp_stats.prev_seq_no = hdr->seq_no;
                }

                clock_gettime(CLOCK_MONOTONIC, &current_time);

                mctp_stats.elapsed_time =
                    (current_time.tv_sec - start_time.tv_sec) +
                    (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
                // Print out the throughputs
                if (mctp_stats.elapsed_time >= DEFAULT_SECONDS_INTERVAL) {
                        mctp_stats.throughput =
                            (float)mctp_stats.total_received_len /
                            ((float)mctp_stats.elapsed_time * 1024);
                        printf("Throughput:%.2fkB/s | Recevied:%lupkts | "
                               "Dropped:%lupkts | "
                               "Invalid:%lupkts\n",
                               mctp_stats.throughput, mctp_stats.packets_count,
                               mctp_stats.packets_dropped,
                               mctp_stats.invalid_payloads);

                        mctp_stats.total_received_len = 0;
                        mctp_stats.packets_count = 0l;
                        mctp_stats.packets_dropped = 0l;
                        mctp_stats.invalid_payloads = 0l;
                        clock_gettime(CLOCK_MONOTONIC, &start_time);
                }
        }

        free(buf);
        close(sd);
        return EXIT_SUCCESS;
}

static int mctp_bench_send(mctp_eid_t eid, size_t len, int net)
{
        struct sockaddr_mctp addr;
        struct sigaction act;
        unsigned char *buf;
        size_t buflen;
        socklen_t addrlen;
        uint32_t sequence = 0;
        struct msg_header *hdr;
        int rc, sd, last_rc;

        struct mctp_ioc_tag_ctl2 ctl = {
            .peer_addr = eid,
            .net = net,
        };

        if (len < sizeof(struct msg_header))
                buflen = MSG_HEADER_SIZE;
        else
                buflen = len;

        sd = socket(AF_MCTP, SOCK_DGRAM, 0);
        if (sd < 0)
                err(EXIT_FAILURE, "send: socket");

        memset(&addr, 0x0, sizeof(addr));
        addrlen = sizeof(addr);
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = net;
        addr.smctp_addr.s_addr = eid;
        addr.smctp_type = 1;
        printf("sending to eid:%d, net:%d, type %d\n", eid,
               (net == 0) ? 1 : net, addr.smctp_type);

        buf = malloc(buflen);
        if (!buf)
                err(EXIT_FAILURE, "send: malloc");

        for (size_t i = MSG_HEADER_SIZE; i < buflen; i++)
                buf[i] = i & 0xff;

        rc = ioctl(sd, SIOCMCTPALLOCTAG2, &ctl);
        if (rc)
                err(EXIT_FAILURE, "send: alloc tag failed");

        memset(&act, 0, sizeof(act));
        act.sa_handler = &handler;
        act.sa_flags = 0;
        if (sigaction(SIGINT, &act, NULL) == -1)
                err(EXIT_FAILURE, "send: sigaction");

        hdr = (struct msg_header *)buf;
        hdr->op_flag = SEND_RUNNING_SIG;
        while (running) {
                addr.smctp_tag = ctl.tag;
                hdr->seq_no = sequence;

                rc = sendto(sd, buf, buflen, 0, (struct sockaddr *)&addr,
                            addrlen);
                if (rc != (int)buflen && rc != last_rc) {
                        last_rc = rc;
                        warn("send: sendto(%zd)", buflen);
                }

                sequence++;
        }

        hdr->op_flag = SEND_TERMINATE_SIG;
        int timeout_seconds = 3000;
        struct pollfd pollfd[1];
        pollfd[0].fd = sd;
        pollfd[0].events = POLLOUT;
        unsigned char *rxbuf;
        rxbuf = malloc(buflen);
        if (!rxbuf)
                err(EXIT_FAILURE, "send: malloc");

        rc = poll(pollfd, 1, timeout_seconds);
        if (rc < 0) {
                warn("send: poll failed");
                goto exit;
        }

        if (pollfd[0].revents & POLLOUT) {
                rc = sendto(sd, buf, buflen, 0, (struct sockaddr *)&addr,
                            addrlen);
                if (rc != (int)buflen) {
                        warn("send: failed to send termination message: %d",
                             rc);
                        goto exit;
                }

                rc = recvfrom(sd, rxbuf, buflen, MSG_TRUNC,
                              (struct sockaddr *)&addr, &addrlen);

                if (rc > 0 && rc == (int)buflen) {
                        printf("send: ACK received\n");
                        goto exit;
                }

                if (rc < 0)
                        warn("send: error receiving ACK");

                if ((size_t)rc != buflen)
                        warn("send: mismatched ACK length, expected:%zd, "
                             "received:%d",
                             buflen, rc);
        }

exit:
        printf("send: terminated\n");
        free(buf);
        close(sd);
        return EXIT_SUCCESS;
}

static void usage(void)
{
        fprintf(stderr, "Usage:\n");
        fprintf(stderr,
                "  mctp-bench recv|send --size=SIZE eid [<NET>],<EID>\n");
        fprintf(stderr, "  Defaults: eid=%d, size=%zd\n", DEFAULT_EID,
                MSG_HEADER_SIZE);
}

bool send_set_net_and_eid(int *mctp_net, mctp_eid_t *eid, char *opt)
{
        char *comma;
        int tmp_int;
        char *endptr;

        for (size_t i = 0; i < strlen(opt); i++) {
                if ((opt[i] < '0' || opt[i] > '9') && opt[i] != ',')
                        return false;
        }
        comma = strchr(opt, ',');

        if (comma) {
                errno = 0;
                tmp_int = strtoul(opt, &endptr, 10);
                if (errno == ERANGE)
                        err(EXIT_FAILURE, "strtol");
                if (endptr == opt)
                        return false;
                *mctp_net = tmp_int;

                comma++;

                errno = 0;
                tmp_int = strtoul(comma, &endptr, 10);
                if (errno == ERANGE)
                        err(EXIT_FAILURE, "strtol");
                if (endptr == comma || *endptr != '\0')
                        return false;
                *eid = tmp_int;
        } else {
                errno = 0;
                tmp_int = strtoul(opt, &endptr, 10);
                if (errno == ERANGE)
                        err(EXIT_FAILURE, "strtol");
                if (endptr == comma || *endptr != '\0')
                        return false;
                *eid = tmp_int;
        }

        return true;
}

int main(int argc, char **argv)
{
        mctp_eid_t eid = DEFAULT_EID;
        int net = 1;
        size_t size = MSG_HEADER_SIZE;
        char *endptr, *optname, *optval;
        int command = 0;

        if (argc < 2) {
                fprintf(stderr, "Error: Missing command\n");
                usage();
                return 255;
        }

        if (strcmp(argv[1], "send") == 0)
                command = 1;
        else if (strcmp(argv[1], "recv") == 0)
                command = 2;
        else {
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
                                if (!send_set_net_and_eid(&net, &eid, optval))
                                        errx(EXIT_FAILURE,
                                             "invalid eid or net value %s",
                                             optval);
                                i++;
                        } else if (strncmp(optname, "--size=", 7) == 0) {
                                optval = argv[i] + 7;
                                size_t tmp = strtoul(optval, &endptr, 0);
                                if (*endptr != '\0' || endptr == optval)
                                        errx(EXIT_FAILURE,
                                             "invalid size value %s", optval);

                                if (tmp >= MSG_HEADER_SIZE)
                                        size = tmp;
                                else {
                                        printf("Min size = 4, setting size to "
                                               "4\n");
                                        size = MSG_HEADER_SIZE;
                                }
                        } else {
                                fprintf(stderr, "Error: Unknown argument: %s\n",
                                        optname);
                                usage();
                                return 255;
                        }
                }

                return mctp_bench_send(eid, size, net);

        case 2: // recv
                if (argc > 2) {
                        fprintf(stderr,
                                "Error: recv does not take any arguments\n");
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