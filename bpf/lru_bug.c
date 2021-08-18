#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") lru_map =
{
      .type        = BPF_MAP_TYPE_LRU_HASH,
      .key_size    = sizeof(__u16),
      .value_size  = sizeof(__u8),
      .max_entries = 10,
      .map_flags   = 0
};
