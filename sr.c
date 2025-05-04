// === Modified from Go-Back-N to Selective Repeat ===
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 12     /* SR requires at least 2 * WINDOWSIZE */
#define NOTINUSE (-1)

int ComputeChecksum(struct pkt packet) {
    int checksum = 0;
    int i;
    for (i = 0; i < 20; i++)
        checksum += (int)(packet.payload[i]);
    checksum += packet.seqnum + packet.acknum;
    return checksum;
}

bool IsCorrupted(struct pkt packet) {
    return packet.checksum != ComputeChecksum(packet);
}

/* === Sender (A) variables for SR === */
static struct pkt send_buffer[SEQSPACE];  /* Store all sent packets */
static bool acked[SEQSPACE];              /* ACK status per packet */
static bool in_use[SEQSPACE];             /* Is this packet slot in use? */
static int base;                          /* Oldest unacked packet */
static int A_nextseqnum;                  /* Next sequence number */

void A_output(struct msg message) {
    int i;
    if ((A_nextseqnum + SEQSPACE - base) % SEQSPACE < WINDOWSIZE) {
        struct pkt sendpkt;
        sendpkt.seqnum = A_nextseqnum;
        sendpkt.acknum = NOTINUSE;
        for (i = 0; i < 20; i++)
            sendpkt.payload[i] = message.data[i];
        sendpkt.checksum = ComputeChecksum(sendpkt);

        send_buffer[A_nextseqnum] = sendpkt;
        in_use[A_nextseqnum] = true;
        acked[A_nextseqnum] = false;

        if (TRACE > 1)
            printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
        if (TRACE == 1)
            printf("Sending packet %d to layer 3\n", A_nextseqnum);

        tolayer3(A, sendpkt);

        // Only start the timer if it's not already running
        static bool timer_running = false;
        if (!timer_running) {
            starttimer(A, RTT);
            timer_running = true;
        }

        A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
    } else {
        if (TRACE > 1)
            printf("----A: New message arrives, send window is full\n");
        window_full++;
    }
}

void A_input(struct pkt packet) {
    int acknum;
    if (!IsCorrupted(packet)) {
        acknum = packet.acknum;
        if (TRACE == 1)
            printf("----A: uncorrupted ACK %d is received\n", acknum);

        if (in_use[acknum] && !acked[acknum]) {
            if (TRACE == 1)
                printf("----A: ACK %d is not a duplicate\n", acknum);

            acked[acknum] = true;
            stoptimer(A);
            new_ACKs++;

            while (acked[base]) {
                in_use[base] = false;
                base = (base + 1) % SEQSPACE;
            }

            if (base != A_nextseqnum) {
                starttimer(A, RTT);
            }
        }
        total_ACKs_received++;
    }
}

void A_timerinterrupt(void) {
    int i;
    for (i = 0; i < SEQSPACE; i++) {
        if (in_use[i] && !acked[i]) {
            if (TRACE == 1)
                printf("----A: Timeout for packet %d. Retransmitting.\n", i);
            tolayer3(A, send_buffer[i]);
            starttimer(A, RTT);
            packets_resent++;
            break;
        }
    }
}

void A_init(void) {
    int i;
    base = 0;
    A_nextseqnum = 0;
    for (i = 0; i < SEQSPACE; i++) {
        acked[i] = false;
        in_use[i] = false;
    }
}

/* === Receiver (B) variables for SR === */
static struct pkt recv_buffer[SEQSPACE];
static bool received[SEQSPACE];
static int expected_base;

void B_input(struct pkt packet) {
    int seq;
    int i;
    struct pkt ackpkt;
    if (!IsCorrupted(packet)) {
        seq = packet.seqnum;
        if (!received[seq]) {
            received[seq] = true;
            recv_buffer[seq] = packet;

            if (TRACE == 1)
                printf("----B: packet %d is correctly received, send ACK!\n", seq);
            packets_received++;

            while (received[expected_base]) {
                tolayer5(B, recv_buffer[expected_base].payload);
                received[expected_base] = false;
                expected_base = (expected_base + 1) % SEQSPACE;
            }
        } else {
            if (TRACE > 1)
                printf("----B: Duplicate packet %d ignored.\n", seq);
        }

        ackpkt.seqnum = NOTINUSE;
        ackpkt.acknum = seq;
        for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
        ackpkt.checksum = ComputeChecksum(ackpkt);
        tolayer3(B, ackpkt);
    } else if (TRACE == 1) {
        printf("----B: corrupted packet received, do nothing!\n");
    }
}

void B_init(void) {
    int i;
    expected_base = 0;
    for (i = 0; i < SEQSPACE; i++)
        received[i] = false;
}

void B_output(struct msg message) {}
void B_timerinterrupt(void) {}
