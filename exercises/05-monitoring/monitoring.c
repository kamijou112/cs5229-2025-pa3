#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_table.h>
#include <rte_hash_crc.h>
#include <rte_tcp.h> // For rte_tcp_hdr
#include <rte_udp.h> // For rte_udp_hdr

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define SHM_NAME "/monitoring_shm"
typedef struct
{
    uint32_t hh_threshold;
    uint32_t drop_threshold;
} Threshold;
Threshold *threshold = NULL;

struct rte_mempool *mbuf_pool = NULL;
struct rte_hash *mac_table = NULL;
void *sketch = NULL;

/* Definitions taken from PA2 */
typedef struct
{
    const char *src_ip;
    const char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} PacketFlow;

/* Function pointers for sketch operations */
void *libsketch_handle = NULL;
void *(*sketch_create)() = NULL;
uint32_t (*sketch_add_item)(void *, const PacketFlow *) = NULL;
uint32_t (*sketch_estimate_frequency)(void *, const PacketFlow *) = NULL;

void load_libsketch_apis()
{
    libsketch_handle = dlopen("./libsketch_impl.so", RTLD_LAZY);
    if (!libsketch_handle)
    {
        RTE_LOG(ERR, USER1, "Failed to load libsketch_impl.so: %s\n Did you copy it to this exercise's directory?\n", dlerror());
        rte_exit(EXIT_FAILURE, "Exiting...\n");
    }

    sketch_create = dlsym(libsketch_handle, "sketch_create");
    sketch_add_item = dlsym(libsketch_handle, "sketch_add_item");
    sketch_estimate_frequency = dlsym(libsketch_handle, "sketch_estimate_frequency");
    RTE_LOG(INFO, USER1, "Loaded libsketch_impl.so and resolved symbols\n");
}

void *create_shm(void)
{
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd == -1)
    {
        perror("shm_open");
        return NULL;
    }

    if (ftruncate(fd, sizeof(Threshold)) == -1)
    {
        perror("ftruncate");
        return NULL;
    }

    void *addr = mmap(0, sizeof(Threshold), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap");
        return NULL;
    }

    close(fd);
    return addr;
}

void initialize_mac_address_table()
{
    // store the mac address and port in the hash table
    if (mac_table == NULL)
    {
        struct rte_hash_parameters hash_params = {
            .name = "mac_table",
            .entries = 1024,
            .key_len = sizeof(struct rte_ether_addr),
            .hash_func = rte_hash_crc,
            .hash_func_init_val = 0,
            .socket_id = rte_socket_id(),
        };
        mac_table = rte_hash_create(&hash_params);
    }

    struct rte_ether_addr *mac1 = malloc(sizeof(struct rte_ether_addr));
    struct rte_ether_addr *mac2 = malloc(sizeof(struct rte_ether_addr));
    struct rte_ether_addr *mac3 = malloc(sizeof(struct rte_ether_addr));
    rte_ether_unformat_addr("08:00:00:00:01:11", mac1);
    rte_ether_unformat_addr("08:00:00:00:02:22", mac2);
    rte_ether_unformat_addr("08:00:00:00:03:33", mac3);

    uint16_t *mac1_data = malloc(sizeof(uint16_t));
    uint16_t *mac2_data = malloc(sizeof(uint16_t));
    uint16_t *mac3_data = malloc(sizeof(uint16_t));
    *mac1_data = 0; // Port 0
    *mac2_data = 1; // Port 1
    *mac3_data = 2; // Port 2
    if (rte_hash_add_key_data(mac_table, mac1, mac1_data) < 0 ||
        rte_hash_add_key_data(mac_table, mac2, mac2_data) < 0 ||
        rte_hash_add_key_data(mac_table, mac3, mac3_data) < 0)
    {
        RTE_LOG(ERR, USER1, "Failed to add MAC addresses to hash table\n");
        free(mac1_data);
        free(mac2_data);
        free(mac3_data);
        return;
    }
    RTE_LOG(INFO, USER1, "Initialized MAC table with two entries\n");
}

void initialize_threshold()
{
    threshold = (Threshold *)create_shm();
    if (threshold == NULL)
    {
        rte_exit(EXIT_FAILURE, "Failed to create shared memory\n");
    }
    threshold->hh_threshold = 10;
    threshold->drop_threshold = 10;
}

void initialize_sketch()
{
    load_libsketch_apis();
    sketch = sketch_create();
    if (sketch == NULL)
    {
        rte_exit(EXIT_FAILURE, "Failed to create sketch\n");
    }
    RTE_LOG(INFO, USER1, "Sketch created successfully\n");
}

// TODO: Your code here (optional)
#define COLLECTOR_PORT_ID 2

// Structure to define a flow key for hash tables
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} FlowKey;

// Structure to store DNS request/response counts
typedef struct {
    uint32_t requests;
    uint32_t responses;
} DnsFlowCounts;

// Global hash tables for HH reporting and DNS flow counts
struct rte_hash *hh_reported_table = NULL;
struct rte_hash *dns_flow_counts_table = NULL;

void initialize_hash_tables() {
    // Initialize Heavy Hitter Reported Table
    struct rte_hash_parameters hh_hash_params = {
        .name = "hh_reported_table",
        .entries = 1024, // Max number of heavy-hitter flows to track
        .key_len = sizeof(FlowKey),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    hh_reported_table = rte_hash_create(&hh_hash_params);
    if (!hh_reported_table) {
        rte_exit(EXIT_FAILURE, "Failed to create HH reported hash table\n");
    }
    RTE_LOG(INFO, USER1, "HH reported hash table created successfully\n");

    // Initialize DNS Flow Counts Table
    struct rte_hash_parameters dns_hash_params = {
        .name = "dns_flow_counts_table",
        .entries = 1024, // Max number of DNS flows to track
        .key_len = sizeof(FlowKey),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    dns_flow_counts_table = rte_hash_create(&dns_hash_params);
    if (!dns_flow_counts_table) {
        rte_exit(EXIT_FAILURE, "Failed to create DNS flow counts hash table\n");
    }
    RTE_LOG(INFO, USER1, "DNS flow counts hash table created successfully\n");
}


void monitoring_main_loop(void)
{
    RTE_LOG(INFO, USER1, "Starting main loop...\n");
    while (1)
    {
        for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail(); port_id++)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
            if (nb_rx == 0)
            {
                continue; // No packets received
            }

            RTE_LOG(INFO, USER1, "Received %u packets on port %u\n", nb_rx, port_id);

            for (uint16_t i = 0; i < nb_rx; i++)
            {
                struct rte_mbuf *mbuf = bufs[i];
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
                if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
                {
                    rte_pktmbuf_free(mbuf);
                    continue;
                }

                // TODO: Your code here
                struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

                // Buffer for IP address strings for PacketFlow (used by sketch)
                char src_ip_str[16];
                char dst_ip_str[16];
                uint32_t src_ip_hbo = rte_be_to_cpu_32(ipv4_hdr->src_addr);
                uint32_t dst_ip_hbo = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
                snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
                             (src_ip_hbo >> 24) & 0xFF, (src_ip_hbo >> 16) & 0xFF,
                             (src_ip_hbo >> 8) & 0xFF, src_ip_hbo & 0xFF);
                snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
                             (dst_ip_hbo >> 24) & 0xFF, (dst_ip_hbo >> 16) & 0xFF,
                             (dst_ip_hbo >> 8) & 0xFF, dst_ip_hbo & 0xFF);

                // Create PacketFlow struct for sketch operations
                PacketFlow flow_for_sketch = {
                    .src_ip = src_ip_str,
                    .dst_ip = dst_ip_str,
                    .protocol = ipv4_hdr->next_proto_id
                };

                // Create FlowKey struct for hash table lookups
                FlowKey flow_key = {
                    .src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr),
                    .dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr),
                    .protocol = ipv4_hdr->next_proto_id
                };

                // Initialize ports to 0 for non-TCP/UDP or if not applicable
                flow_for_sketch.src_port = 0;
                flow_for_sketch.dst_port = 0;
                flow_key.src_port = 0;
                flow_key.dst_port = 0;

                // Extract transport layer ports if UDP or TCP
                if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
                    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                    flow_for_sketch.src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                    flow_for_sketch.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                    flow_key.src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                    flow_key.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                } else if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                    flow_for_sketch.src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
                    flow_for_sketch.dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                    flow_key.src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
                    flow_key.dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                }

                 // -----------------------------------------------------------
                // Heavy-Hitter Detection
                // -----------------------------------------------------------
                uint32_t current_freq = sketch_add_item(sketch, &flow_for_sketch);

                if (current_freq > threshold->hh_threshold) {
                    // Check if this flow has already been reported as HH
                    uint8_t *reported_flag = NULL;
                    if (rte_hash_lookup_data(hh_reported_table, &flow_key, (void **)&reported_flag) < 0) {
                        // Flow not reported yet, so report it
                        uint8_t new_flag = 1;
                        if (rte_hash_add_key_data(hh_reported_table, &flow_key, &new_flag) < 0) {
                            RTE_LOG(ERR, USER1, "Failed to add HH flow to reported table\n");
                        } else {
                            // Clone mbuf for mirroring to collector
                            struct rte_mbuf *mirror_mbuf = rte_pktmbuf_clone(mbuf, mbuf_pool);
                            if (mirror_mbuf) {
                                if (rte_eth_tx_burst(COLLECTOR_PORT_ID, 0, &mirror_mbuf, 1) < 1) {
                                    RTE_LOG(ERR, USER1, "Failed to mirror packet to collector port %u\n", COLLECTOR_PORT_ID);
                                    rte_pktmbuf_free(mirror_mbuf); // Free if transmission fails
                                } else {
                                    RTE_LOG(INFO, USER1, "重度流量包镜像到端口 %u\n", COLLECTOR_PORT_ID);
                                }
                            } else {
                                RTE_LOG(ERR, USER1, "克隆 mbuf 失败，无法镜像重度流量\n");
                            }
                        }
                    }
                }

                // DNS Amplification Attack Mitigation
                bool dropped = false;
                if (flow_key.protocol == IPPROTO_UDP && (flow_key.src_port == 53 || flow_key.dst_port == 53)) {
                    // Create a canonical flow key for DNS request-response pairs
                    // If it's a response (src_port == 53), swap src/dst IP and ports to make it canonical (client->server view)
                    FlowKey dns_canonical_flow_key = flow_key;

                    if (flow_key.src_port == 53) { // This is a DNS response
                        // Swap src and dst to get the "request" side of the flow for canonical key
                        uint32_t temp_ip = dns_canonical_flow_key.src_ip;
                        dns_canonical_flow_key.src_ip = dns_canonical_flow_key.dst_ip;
                        dns_canonical_flow_key.dst_ip = temp_ip;

                        uint16_t temp_port = dns_canonical_flow_key.src_port;
                        dns_canonical_flow_key.src_port = dns_canonical_flow_key.dst_port;
                        dns_canonical_flow_key.dst_port = temp_port;
                    }
                    // Now dns_canonical_flow_key represents the (client_ip, server_ip, client_port, 53, UDP) form

                    DnsFlowCounts *dns_counts = NULL;
                    int ret = rte_hash_lookup_data(dns_flow_counts_table, &dns_canonical_flow_key, (void **)&dns_counts);

                    if (ret < 0) { // Flow not found, initialize counts and add to table
                        DnsFlowCounts new_counts = { .requests = 0, .responses = 0 };
                        if (flow_key.dst_port == 53) { // It's a DNS request
                            new_counts.requests = 1;
                        } else if (flow_key.src_port == 53) { // It's a DNS response
                            new_counts.responses = 1;
                        }
                        if (rte_hash_add_key_data(dns_flow_counts_table, &dns_canonical_flow_key, &new_counts) < 0) {
                            RTE_LOG(ERR, USER1, "添加 DNS 流到计数表失败\n");
                        }
                    } else { // Flow found, update counts
                        if (flow_key.dst_port == 53) { // It's a DNS request
                            dns_counts->requests++;
                        } else if (flow_key.src_port == 53) { // It's a DNS response
                            dns_counts->responses++;
                        }

                        // Check for DNS amplification attack
                        if (dns_counts->responses > (dns_counts->requests + threshold->drop_threshold)) {
                            RTE_LOG(INFO, USER1, "丢弃 DNS 响应包，可能存在放大攻击。流: %s:%hu -> %s:%hu\n",
                                    src_ip_str, flow_key.src_port, dst_ip_str, flow_key.dst_port);
                            rte_pktmbuf_free(mbuf);
                            dropped = true;
                        }
                    }
                }

                if (dropped) {
                    continue; // Packet was dropped, move to next packet
                }

                uint16_t *destination_port = NULL;
                RTE_LOG(INFO, USER1, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                        eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                        eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
                if (rte_hash_lookup_data(mac_table, &eth_hdr->dst_addr, (void **)&destination_port) < 0)
                {
                    RTE_LOG(ERR, USER1, "MAC address not found in hash table\n");
                    rte_pktmbuf_free(mbuf);
                }
                RTE_LOG(INFO, USER1, "Packet received on port %u, destined for port %u\n", port_id, destination_port ? *destination_port : -1);

                if (destination_port != NULL)
                {
                    if (rte_eth_tx_burst(*destination_port, 0, &mbuf, 1) < 1)
                    {
                        RTE_LOG(ERR, USER1, "Failed to send packet on port %u\n", *destination_port);
                        rte_pktmbuf_free(mbuf);
                    }
                    else
                    {
                        RTE_LOG(INFO, USER1, "Packet sent to port %u\n", *destination_port);
                    }
                }
                else
                {
                    rte_pktmbuf_free(mbuf);
                    RTE_LOG(ERR, USER1, "Destination port is NULL\n");
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    uint16_t num_ports = rte_eth_dev_count_avail();
    if (num_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    RTE_LOG(INFO, USER1, "Number of available ports: %u\n", num_ports);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "mbuf_pool creation failed\n");

    for (uint16_t port_id = 0; port_id < num_ports; port_id++)
    {
        struct rte_eth_conf port_conf = {0};
        if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) != 0)
            rte_exit(EXIT_FAILURE, "Failed to configure device\n");

        if (rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_socket_id(), NULL, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Failed to setup RX queue\n");

        if (rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, rte_socket_id(), NULL) != 0)
            rte_exit(EXIT_FAILURE, "Failed to setup TX queue\n");

        if (rte_eth_dev_start(port_id) < 0)
            rte_exit(EXIT_FAILURE, "Failed to start device\n");
    }

    initialize_mac_address_table();
    initialize_threshold();
    initialize_sketch();
    initialize_hash_tables(); 

    monitoring_main_loop();
    return 0;
}
