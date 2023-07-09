/*
 * Copyright (c) 2023, Tim Schumacher <timschumi@gmx.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibExt4/Superblock.h>

namespace Ext4 {

ErrorOr<void> Superblock::validate() const
{
    if (m_magic != MAGIC)
        return Error::from_string_view("Superblock does not have a valid ext4 magic"sv);

    if (!has_flag(read_only_feature_set(), ReadOnlyFeatureSet::BigAlloc)) {
        // If bigalloc is not enabled, the encoded cluster size must equal the encoded block size.
        if (m_encoded_cluster_size != m_encoded_block_size)
            return Error::from_string_view("Encoded cluster size does not equal encoded block size in a superblock without bigalloc"sv);

        // If bigalloc is not enabled, the cluster count per group must equal the block count per group.
        if (m_clusters_per_group != m_blocks_per_group)
            return Error::from_string_view("Cluster count per group does not equal block count per group in a superblock without bigalloc"sv);
    }

    if (m_metadata_checksum_type != 1)
        return Error::from_string_view("Metadata checksum type in ext4 superblock is not CRC32C"sv);

    if (has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::ReservedGDTBlocks) && !has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::SparseSuperblocks))
        return Error::from_string_view("Superblock claims support of reserved GDT blocks without sparse superblocks"sv);

    // TODO: Calculate and check the superblock checksum.

    return {};
}

}
