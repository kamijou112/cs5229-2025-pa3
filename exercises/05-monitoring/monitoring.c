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

    monitoring_main_loop();
    return 0;
}
