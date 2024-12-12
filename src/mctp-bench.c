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

struct mctp_bench_send_args {
        mctp_eid_t eid;
        size_t len;
        int net;
};

struct msg_header {
        uint8_t op_flag;
        uint32_t seq_no;
};

struct mctp_stats {
        double elapsed_time;
        unsigned long packets_dropped;
        unsigned long packets_count;
        unsigned long invalid_payloads;
        ssize_t total_received_len;
        ssize_t curr_packet_len;
        uint32_t prev_seq_no;
};

static const mctp_eid_t DEFAULT_EID = 8;
static const size_t MSG_HEADER_SIZE = sizeof(struct msg_header);
static const int DEFAULT_NET = 1;
static const int DEFAULT_SECONDS_INTERVAL = 10;
static const uint8_t SEND_TERMINATE_SIG = 0;
static const uint8_t SEND_RUNNING_SIG = 1;

static void print_stats(struct mctp_stats mctp_stats)
{
        float throughput = (float)mctp_stats.total_received_len /
                           ((float)mctp_stats.elapsed_time * 1024);
        printf("Throughput:%.2fkB/s | Recevied:%lupkts | "
               "Dropped:%lupkts | "
               "Invalid:%lupkts\n",
               throughput, mctp_stats.packets_count, mctp_stats.packets_dropped,
               mctp_stats.invalid_payloads);
}

static int get_elapsed_time(struct timespec start_time,
                            struct timespec current_time)
{
        return (current_time.tv_sec - start_time.tv_sec) +
               (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
}

static int get_timeout(struct timespec start_time, struct timespec current_time)
{
        unsigned int current_sec = current_time.tv_sec;
        unsigned int start_sec = start_time.tv_sec;
        int time_to_print_sec =
            (DEFAULT_SECONDS_INTERVAL) - (current_sec - start_sec);
        return (time_to_print_sec > 0) ? time_to_print_sec * 1000 : 0;
}

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
                int timeout;
                struct pollfd pollfd[1];
                pollfd[0].fd = sd;
                pollfd[0].events = POLLIN;

                if (started_recv_flag) {
                        clock_gettime(CLOCK_MONOTONIC, &current_time);
                        timeout = get_timeout(start_time, current_time);
                } else {
                        timeout = -1;
                }

                rc = poll(pollfd, 1, timeout);
                if (rc < 0) {
                        warn("recv: poll failed");
                        goto exit;
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
                                goto sender_terminated;
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
                    get_elapsed_time(start_time, current_time);
                if (mctp_stats.elapsed_time >= DEFAULT_SECONDS_INTERVAL) {
                        print_stats(mctp_stats);
                        mctp_stats.total_received_len = 0;
                        mctp_stats.packets_count = 0l;
                        mctp_stats.packets_dropped = 0l;
                        mctp_stats.invalid_payloads = 0l;
                        clock_gettime(CLOCK_MONOTONIC, &start_time);
                }
        }

sender_terminated:
        printf("recv: sender terminating signal "
               "received\n");
        addr.smctp_tag &= ~MCTP_TAG_OWNER;

        rc = sendto(sd, buf, buflen, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (rc != (int)mctp_stats.curr_packet_len) {
                warn("recv: sendto");
        }
        printf("recv: ACK sent\n");
exit:
        free(buf);
        close(sd);
        return EXIT_SUCCESS;
}

static int mctp_bench_send(struct mctp_bench_send_args send_args)
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
            .peer_addr = send_args.eid,
            .net = send_args.net,
        };

        buflen =
            (send_args.len < MSG_HEADER_SIZE) ? MSG_HEADER_SIZE : send_args.len;

        sd = socket(AF_MCTP, SOCK_DGRAM, 0);
        if (sd < 0)
                err(EXIT_FAILURE, "send: socket");

        memset(&addr, 0x0, sizeof(addr));
        addrlen = sizeof(addr);
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = send_args.net;
        addr.smctp_addr.s_addr = send_args.eid;
        addr.smctp_type = 1;
        printf("send: to eid %d, net %d, type %d\n", send_args.eid,
               send_args.net, addr.smctp_type);

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

static void recv_usage(void) { fprintf(stderr, "'mctp-bench recv'\n"); }

static void send_usage(void)
{
        fprintf(stderr, "'mctp-bench send --size=SIZE eid [<NET>],[<EID>]'\n");
        fprintf(stderr, "defaults: eid=%d, size=%zd\n", DEFAULT_EID,
                MSG_HEADER_SIZE);
}

bool send_set_net_and_eid(struct mctp_bench_send_args *send_args, char *opt)
{
        char *comma;
        char *endptr;
        int tmp;

        for (size_t i = 0; i < strlen(opt); i++) {
                if ((opt[i] < '0' || opt[i] > '9') && opt[i] != ',')
                        return false;
        }
        comma = strchr(opt, ',');

        errno = 0;
        tmp = strtoul(opt, &endptr, 10);
        if (errno == ERANGE)
                err(EXIT_FAILURE, "strtol");
        if (endptr == opt)
                return false;

        if (comma) {
                send_args->net = tmp;
                comma++;

                errno = 0;
                tmp = strtoul(comma, &endptr, 10);
                if (errno == ERANGE)
                        err(EXIT_FAILURE, "strtol");
                if (endptr == comma || *endptr != '\0')
                        return false;
        }
        send_args->eid = tmp;
        return true;
}

int main(int argc, char **argv)
{
        struct mctp_bench_send_args send_args = {
            .eid = DEFAULT_EID,
            .len = MSG_HEADER_SIZE,
            .net = DEFAULT_NET,
        };
        char *endptr, *optname, *optval;
        int command = 0;

        if (argc < 2 || argc > 5) {
                fprintf(stderr, "%s\n",
                        (argc < 2) ? "Error: Missing command"
                                   : "Error: Too many arguments");
                recv_usage();
                send_usage();
                return 255;
        }

        if (strcmp(argv[1], "send") == 0)
                command = 1;
        else if (strcmp(argv[1], "recv") == 0)
                command = 2;
        else {
                fprintf(stderr, "Error: Unknown command: %s\n", argv[1]);
                recv_usage();
                send_usage();
                return 255;
        }

        switch (command) {
        case 1: // send
                for (int i = 2; i < argc; i++) {
                        optname = argv[i];
                        if (strcmp(optname, "eid") == 0) {
                                optval = argv[i + 1];
                                if (!send_set_net_and_eid(&send_args, optval))
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

                                if (tmp > MSG_HEADER_SIZE)
                                        send_args.len = tmp;
                                else {
                                        printf(
                                            "Min size=%zd, size set to %zd\n",
                                            MSG_HEADER_SIZE, MSG_HEADER_SIZE);
                                        send_args.len = MSG_HEADER_SIZE;
                                }
                        } else {
                                fprintf(stderr, "send: unknown argument: %s\n",
                                        optname);
                                send_usage();
                                return 255;
                        }
                }

                return mctp_bench_send(send_args);

        case 2: // recv
                if (argc > 2) {
                        fprintf(stderr,
                                "recv: does not take extra arguments\n");
                        recv_usage();
                        return 255;
                }

                return mctp_bench_recv();

        default:
                fprintf(stderr, "Error: Invalid command\n");
                recv_usage();
                send_usage();
                return 255;
        }

        return EXIT_FAILURE;
}