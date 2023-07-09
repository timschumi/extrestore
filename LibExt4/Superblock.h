/*
 * Copyright (c) 2023, Tim Schumacher <timschumi@gmx.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Endian.h>
#include <AK/IntegralMath.h>
#include <AK/Time.h>
#include <AK/UFixedBigInt.h>
#include <AK/UUID.h>

namespace Ext4 {

// https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#The_Super_Block

enum class FileSystemState : u16 {
    CleanlyUnmounted = 0x0001,
    ErrorsDetected = 0x0002,
    OrphansBeingRecovered = 0x0004,
};
AK_ENUM_BITWISE_OPERATORS(FileSystemState);

enum class ErrorDetectionBehavior : u16 {
    Continue = 1,
    ReadOnly = 2,
    Panic = 3,
};

enum class CreatorOS : u32 {
    Linux = 0,
    Hurd = 1,
    Masix = 2,
    FreeBSD = 3,
    Lites = 4,
};

enum class RevisionLevel : u32 {
    Original = 0,
    V2 = 1,
};

enum class CompatibleFeatureSet : u32 {
    DirectoryPreallocation = 0x1,
    ImagicInodes = 0x2,
    Journal = 0x4,
    ExtendedAttributes = 0x8,
    ReservedGDTBlocks = 0x10,
    IndexedDirectories = 0x20,
    LazyBG = 0x40,
    ExcludeInode = 0x80,
    ExcludeBitmap = 0x100,
    SparseSuperBlockV2 = 0x200,
};
AK_ENUM_BITWISE_OPERATORS(CompatibleFeatureSet);

enum class IncompatibleFeatureSet : u32 {
    Compression = 0x1,
    DirectoryEntryFileType = 0x2,
    JournalRecovery = 0x4,
    JournalDevice = 0x8,
    MetaBlockGroups = 0x10,
    Extents = 0x40,
    SixtyFourBits = 0x80,
    MultipleMountProtection = 0x100,
    FlexibleBlockGroups = 0x200,
    LargeExtendedAttributes = 0x400,
    DirectoryEntryDataField = 0x1000,
    ChecksumSeed = 0x2000,
    LargeDirectories = 0x4000,
    InlineData = 0x8000,
    EncryptedInodes = 0x10000,
};
AK_ENUM_BITWISE_OPERATORS(IncompatibleFeatureSet);

enum class ReadOnlyFeatureSet : u32 {
    SparseSuperblocks = 0x1,
    LargeFiles = 0x2,
    HugeFiles = 0x8,
    GroupDescriptorChecksums = 0x10,
    NoLinkLimit = 0x20,
    LargeInodes = 0x40,
    Snapshots = 0x80,
    Quota = 0x100,
    BigAlloc = 0x200,
    MetadataChecksum = 0x400,
    Replicas = 0x800,
    ReadOnly = 0x1000,
    ProjectQuotas = 0x2000,
};
AK_ENUM_BITWISE_OPERATORS(ReadOnlyFeatureSet);

enum class HashAlgorithm : u8 {
    Legacy = 0x0,
    HalfMD4 = 0x1,
    Tea = 0x2,
    LegacyUnsigned = 0x3,
    HalfMD4Unsigned = 0x4,
    TeaUnsigned = 0x5,
};

enum class MountOption : u32 {
    Debug = 0x0001,
    InheritGroupFromDirectory = 0x0002,
    UserspaceExtendedAttributes = 0x0004,
    AccessControlLists = 0x0008,
    Only16BitUID = 0x0010,
    JournalData = 0x0020,
    JournalOrdered = 0x0040,
    NoBarrier = 0x0100,
    TrackMetadataBlocks = 0x0200,
    Discard = 0x0400,
    DisableDelayedAllocation = 0x0800,
};
AK_ENUM_BITWISE_OPERATORS(MountOption);

enum class Flags : u32 {
    UsingSignedDirectoryHash = 0x0001,
    UsingUnsignedDirectoryHash = 0x0002,
    TestDevelopmentCode = 0x0004,
};
AK_ENUM_BITWISE_OPERATORS(Flags);

enum class MetadataChecksumType : u8 {
    CRC32C = 1,
};

enum class EncryptionAlgorithm : u8 {
    Invalid = 0,
    AES256XTS = 1,
    AES256GCM = 2,
    AES256CBC = 3,
};

class [[gnu::packed]] Superblock {
private:
    static constexpr u16 MAGIC = 0xEF53;
    static constexpr size_t UUID_SIZE = 16;
    static constexpr size_t VOLUME_LABEL_SIZE = 16;
    static constexpr size_t LAST_MOUNTED_PATH_SIZE = 64;
    static constexpr size_t JOURNAL_BLOCKS_SIZE = 17;
    static constexpr size_t ERROR_FUNCTION_NAME_SIZE = 32;
    static constexpr size_t MOUNT_OPTIONS_STRING_SIZE = 64;
    static constexpr size_t ENCRYPTION_ALGORITHM_COUNT = 4;
    static constexpr size_t ENCRYPTION_PASSWORD_SALT_SIZE = 16;

public:
    ErrorOr<void> validate() const;

    [[nodiscard]] u32 inode_count() const
    {
        return m_inode_count;
    }

    [[nodiscard]] u64 block_count() const
    {
        if (has_flag(incompatible_feature_set(), IncompatibleFeatureSet::SixtyFourBits))
            return (static_cast<u64>(m_block_count_high) << 32) | m_block_count_low;

        return m_block_count_low;
    }

    [[nodiscard]] u64 reserved_block_count() const
    {
        if (has_flag(incompatible_feature_set(), IncompatibleFeatureSet::SixtyFourBits))
            return (static_cast<u64>(m_reserved_block_count_high) << 32) | m_reserved_block_count_low;

        return m_reserved_block_count_low;
    }

    [[nodiscard]] u64 free_block_count() const
    {
        if (has_flag(incompatible_feature_set(), IncompatibleFeatureSet::SixtyFourBits))
            return (static_cast<u64>(m_free_block_count_high) << 32) | m_free_block_count_low;

        return m_free_block_count_low;
    }

    [[nodiscard]] u32 free_inode_count() const
    {
        return m_free_inode_count;
    }

    [[nodiscard]] u32 first_data_block() const
    {
        return m_first_data_block;
    }

    [[nodiscard]] u32 block_size() const
    {
        return AK::pow<u32>(2, 10 + m_encoded_block_size);
    }

    [[nodiscard]] u32 cluster_size() const
    {
        VERIFY(has_flag(read_only_feature_set(), ReadOnlyFeatureSet::BigAlloc));
        return AK::pow<u32>(2, m_encoded_cluster_size);
    }

    [[nodiscard]] u32 blocks_per_group() const
    {
        return m_blocks_per_group;
    }

    [[nodiscard]] u32 clusters_per_group() const
    {
        VERIFY(has_flag(read_only_feature_set(), ReadOnlyFeatureSet::BigAlloc));
        return m_clusters_per_group;
    }

    [[nodiscard]] u32 inodes_per_group() const
    {
        return m_inodes_per_group;
    }

    [[nodiscard]] UnixDateTime mount_time() const
    {
        return UnixDateTime::from_seconds_since_epoch(m_mount_time);
    }

    [[nodiscard]] UnixDateTime write_time() const
    {
        return UnixDateTime::from_seconds_since_epoch(m_write_time);
    }

    [[nodiscard]] u16 mounts_since_last_fsck() const
    {
        return m_mounts_since_last_fsck;
    }

    [[nodiscard]] u16 maximum_mounts_since_last_fsck() const
    {
        return m_maximum_mounts_since_last_fsck;
    }

    [[nodiscard]] FileSystemState file_system_state() const
    {
        return bit_cast<FileSystemState>(static_cast<u16>(m_file_system_state));
    }

    [[nodiscard]] ErrorDetectionBehavior error_detection_behavior() const
    {
        return bit_cast<ErrorDetectionBehavior>(static_cast<u16>(m_error_detection_behavior));
    }

    [[nodiscard]] u16 minor_revision_level() const
    {
        return m_minor_revision_level;
    }

    [[nodiscard]] UnixDateTime last_check_time() const
    {
        return UnixDateTime::from_seconds_since_epoch(m_last_check_time);
    }

    [[nodiscard]] Duration maximum_last_check_interval() const
    {
        return Duration::from_seconds(m_maximum_last_check_interval);
    }

    [[nodiscard]] CreatorOS creator_os() const
    {
        return bit_cast<CreatorOS>(static_cast<u32>(m_creator_os));
    }

    [[nodiscard]] RevisionLevel revision_level() const
    {
        return bit_cast<RevisionLevel>(static_cast<u32>(m_revision_level));
    }

    [[nodiscard]] u16 reserved_blocks_default_uid() const
    {
        return m_reserved_blocks_default_uid;
    }

    [[nodiscard]] u16 reserved_blocks_default_gid() const
    {
        return m_reserved_blocks_default_gid;
    }

    [[nodiscard]] u32 first_inode() const
    {
        VERIFY(revision_level() >= Ext4::RevisionLevel::V2);
        return m_first_inode;
    }

    [[nodiscard]] u16 inode_size() const
    {
        VERIFY(revision_level() >= Ext4::RevisionLevel::V2);
        return m_inode_size;
    }

    [[nodiscard]] u16 block_group_number() const
    {
        return m_block_group_number;
    }

    [[nodiscard]] CompatibleFeatureSet compatible_feature_set() const
    {
        return bit_cast<CompatibleFeatureSet>(static_cast<u32>(m_compatible_feature_set));
    }

    [[nodiscard]] IncompatibleFeatureSet incompatible_feature_set() const
    {
        return bit_cast<IncompatibleFeatureSet>(static_cast<u32>(m_incompatible_feature_set));
    }

    [[nodiscard]] ReadOnlyFeatureSet read_only_feature_set() const
    {
        return bit_cast<ReadOnlyFeatureSet>(static_cast<u32>(m_read_only_feature_set));
    }

    [[nodiscard]] UUID uuid() const
    {
        return m_uuid;
    }

    [[nodiscard]] StringView volume_label() const
    {
        return { m_volume_label.data(), min(__builtin_strlen(m_volume_label.data()), m_volume_label.size()) };
    }

    [[nodiscard]] StringView last_mounted_path() const
    {
        return { m_last_mounted_path.data(), min(__builtin_strlen(m_last_mounted_path.data()), m_last_mounted_path.size()) };
    }

    [[nodiscard]] u32 algorithm_usage_bitmap() const
    {
        return m_algorithm_usage_bitmap;
    }

    [[nodiscard]] u8 preallocated_file_blocks() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::DirectoryPreallocation));
        return m_preallocated_file_blocks;
    }

    [[nodiscard]] u8 preallocated_directory_blocks() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::DirectoryPreallocation));
        return m_preallocated_directory_blocks;
    }

    [[nodiscard]] u16 reserved_gdt_blocks() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::ReservedGDTBlocks));
        return m_reserved_gdt_blocks;
    }

    [[nodiscard]] UUID journal_superblock_uuid() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::Journal));
        return m_journal_superblock_uuid;
    }

    [[nodiscard]] u32 journal_inode_number() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::Journal));
        return m_journal_inode_number;
    }

    [[nodiscard]] u32 journal_device_number() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::Journal));
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::JournalDevice));
        return m_journal_device_number;
    }

    [[nodiscard]] u32 last_orphan() const
    {
        return m_last_orphan;
    }

    [[nodiscard]] HashAlgorithm default_directory_hash_algorithm() const
    {
        return bit_cast<HashAlgorithm>(m_default_directory_hash_algorithm);
    }

    [[nodiscard]] u16 group_descriptor_size() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::SixtyFourBits));
        return m_group_descriptor_size;
    }

    [[nodiscard]] MountOption default_mount_options() const
    {
        return bit_cast<MountOption>(static_cast<u32>(m_default_mount_options));
    }

    [[nodiscard]] u32 first_meta_block_group() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::MetaBlockGroups));
        return m_first_meta_block_group;
    }

    [[nodiscard]] UnixDateTime creation_time() const
    {
        return UnixDateTime::from_seconds_since_epoch(m_creation_time);
    }

    [[nodiscard]] u16 minimum_extra_inode_size() const
    {
        return m_minimum_extra_inode_size;
    }

    [[nodiscard]] u16 wanted_extra_inode_size() const
    {
        return m_wanted_extra_inode_size;
    }

    [[nodiscard]] Flags flags() const
    {
        return bit_cast<Flags>(static_cast<u32>(m_flags));
    }

    [[nodiscard]] u16 raid_stride_blocks() const
    {
        return m_raid_stride_blocks;
    }

    [[nodiscard]] u16 multi_mount_protection_interval() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::MultipleMountProtection));
        return m_multi_mount_protection_interval;
    }

    [[nodiscard]] u64 multi_mount_protection_block() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::MultipleMountProtection));
        return m_multi_mount_protection_block;
    }

    [[nodiscard]] u32 raid_stripe_width() const
    {
        return m_raid_stripe_width;
    }

    [[nodiscard]] u8 flexible_block_group_size() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::FlexibleBlockGroups));
        return AK::pow<u8>(2, m_encoded_flexible_block_group_size);
    }

    [[nodiscard]] MetadataChecksumType metadata_checksum_type() const
    {
        return bit_cast<MetadataChecksumType>(m_metadata_checksum_type);
    }

    [[nodiscard]] u64 written_kibibytes() const
    {
        return m_written_kibibytes;
    }

    [[nodiscard]] u32 active_snapshot_inode() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::Snapshots));
        return m_active_snapshot_inode;
    }

    [[nodiscard]] u32 active_snapshot_id() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::Snapshots));
        return m_active_snapshot_id;
    }

    [[nodiscard]] u64 active_snapshot_reserved_blocks() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::Snapshots));
        return m_active_snapshot_reserved_blocks;
    }

    [[nodiscard]] u32 snapshot_list() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::Snapshots));
        return m_snapshot_list;
    }

    [[nodiscard]] u32 error_count() const
    {
        return m_error_count;
    }

    [[nodiscard]] UnixDateTime first_error_time() const
    {
        return UnixDateTime::from_seconds_since_epoch(m_first_error_time);
    }

    [[nodiscard]] u32 first_error_inode() const
    {
        return m_first_error_inode;
    }

    [[nodiscard]] u64 first_error_block() const
    {
        return m_first_error_block;
    }

    [[nodiscard]] StringView first_error_function_name() const
    {
        return { m_first_error_function_name.data(), min(__builtin_strlen(m_first_error_function_name.data()), m_first_error_function_name.size()) };
    }

    [[nodiscard]] u32 first_error_line_number() const
    {
        return m_first_error_line_number;
    }

    [[nodiscard]] UnixDateTime last_error_time() const
    {
        return UnixDateTime::from_seconds_since_epoch(m_last_error_time);
    }

    [[nodiscard]] u32 last_error_inode() const
    {
        return m_last_error_inode;
    }

    [[nodiscard]] u32 last_error_line_number() const
    {
        return m_last_error_line_number;
    }

    [[nodiscard]] u64 last_error_block() const
    {
        return m_last_error_block;
    }

    [[nodiscard]] StringView last_error_function_name() const
    {
        return { m_last_error_function_name.data(), min(__builtin_strlen(m_last_error_function_name.data()), m_last_error_function_name.size()) };
    }

    [[nodiscard]] StringView mount_options_string() const
    {
        return { m_mount_options_string.data(), min(__builtin_strlen(m_mount_options_string.data()), m_mount_options_string.size()) };
    }

    [[nodiscard]] u32 user_quota_inode_number() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::Quota));
        return m_user_quota_inode_number;
    }

    [[nodiscard]] u32 group_quota_inode_number() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::Quota));
        return m_group_quota_inode_number;
    }

    [[nodiscard]] u32 overhead_blocks() const
    {
        return m_overhead_blocks;
    }

    [[nodiscard]] Array<u32, 2> superblock_backup_groups() const
    {
        VERIFY(has_flag(compatible_feature_set(), Ext4::CompatibleFeatureSet::SparseSuperBlockV2));
        return {
            m_superblock_backup_group_1,
            m_superblock_backup_group_2,
        };
    }

    [[nodiscard]] Array<EncryptionAlgorithm, ENCRYPTION_ALGORITHM_COUNT> encryption_algorithms() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::EncryptedInodes));
        static_assert(ENCRYPTION_ALGORITHM_COUNT == 4);
        return {
            bit_cast<EncryptionAlgorithm>(m_encryption_algorithms[0]),
            bit_cast<EncryptionAlgorithm>(m_encryption_algorithms[1]),
            bit_cast<EncryptionAlgorithm>(m_encryption_algorithms[2]),
            bit_cast<EncryptionAlgorithm>(m_encryption_algorithms[3]),
        };
    }

    [[nodiscard]] ReadonlyBytes encryption_password_salt() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::EncryptedInodes));
        return m_encryption_password_salt;
    }

    [[nodiscard]] u32 lost_and_found_inode_number() const
    {
        return m_lost_and_found_inode_number;
    }

    [[nodiscard]] u32 project_quota_inode_number() const
    {
        VERIFY(has_flag(read_only_feature_set(), Ext4::ReadOnlyFeatureSet::ProjectQuotas));
        return m_project_quota_inode_number;
    }

    [[nodiscard]] u32 checksum_seed() const
    {
        VERIFY(has_flag(incompatible_feature_set(), Ext4::IncompatibleFeatureSet::ChecksumSeed));
        return m_checksum_seed;
    }

    [[nodiscard]] u32 checksum() const
    {
        return m_checksum;
    }

private:
    LittleEndian<u32> m_inode_count;
    LittleEndian<u32> m_block_count_low;
    LittleEndian<u32> m_reserved_block_count_low;
    LittleEndian<u32> m_free_block_count_low;
    LittleEndian<u32> m_free_inode_count;
    LittleEndian<u32> m_first_data_block;
    LittleEndian<u32> m_encoded_block_size;
    LittleEndian<u32> m_encoded_cluster_size;
    LittleEndian<u32> m_blocks_per_group;
    LittleEndian<u32> m_clusters_per_group;
    LittleEndian<u32> m_inodes_per_group;
    LittleEndian<u32> m_mount_time;
    LittleEndian<u32> m_write_time;
    LittleEndian<u16> m_mounts_since_last_fsck;
    LittleEndian<u16> m_maximum_mounts_since_last_fsck;
    LittleEndian<u16> m_magic;
    LittleEndian<u16> m_file_system_state;
    LittleEndian<u16> m_error_detection_behavior;
    LittleEndian<u16> m_minor_revision_level;
    LittleEndian<u32> m_last_check_time;
    LittleEndian<u32> m_maximum_last_check_interval;
    LittleEndian<u32> m_creator_os;
    LittleEndian<u32> m_revision_level;
    LittleEndian<u16> m_reserved_blocks_default_uid;
    LittleEndian<u16> m_reserved_blocks_default_gid;
    LittleEndian<u32> m_first_inode;
    LittleEndian<u16> m_inode_size;
    LittleEndian<u16> m_block_group_number;
    LittleEndian<u32> m_compatible_feature_set;
    LittleEndian<u32> m_incompatible_feature_set;
    LittleEndian<u32> m_read_only_feature_set;
    Array<u8, UUID_SIZE> m_uuid;
    Array<char, VOLUME_LABEL_SIZE> m_volume_label;
    Array<char, LAST_MOUNTED_PATH_SIZE> m_last_mounted_path;
    LittleEndian<u32> m_algorithm_usage_bitmap;
    u8 m_preallocated_file_blocks;
    u8 m_preallocated_directory_blocks;
    LittleEndian<u16> m_reserved_gdt_blocks;
    Array<u8, UUID_SIZE> m_journal_superblock_uuid;
    LittleEndian<u32> m_journal_inode_number;
    LittleEndian<u32> m_journal_device_number;
    LittleEndian<u32> m_last_orphan;
    LittleEndian<u32> m_hash_seed[4];
    u8 m_default_directory_hash_algorithm;
    u8 m_journal_backup_type;
    LittleEndian<u16> m_group_descriptor_size;
    LittleEndian<u32> m_default_mount_options;
    LittleEndian<u32> m_first_meta_block_group;
    LittleEndian<u32> m_creation_time;
    LittleEndian<u32> m_journal_blocks[JOURNAL_BLOCKS_SIZE];
    LittleEndian<u32> m_block_count_high;
    LittleEndian<u32> m_reserved_block_count_high;
    LittleEndian<u32> m_free_block_count_high;
    LittleEndian<u16> m_minimum_extra_inode_size;
    LittleEndian<u16> m_wanted_extra_inode_size;
    LittleEndian<u32> m_flags;
    LittleEndian<u16> m_raid_stride_blocks;
    LittleEndian<u16> m_multi_mount_protection_interval;
    LittleEndian<u64> m_multi_mount_protection_block;
    LittleEndian<u32> m_raid_stripe_width;
    u8 m_encoded_flexible_block_group_size;
    u8 m_metadata_checksum_type;
    u8 _padding[2];
    LittleEndian<u64> m_written_kibibytes;
    LittleEndian<u32> m_active_snapshot_inode;
    LittleEndian<u32> m_active_snapshot_id;
    LittleEndian<u64> m_active_snapshot_reserved_blocks;
    LittleEndian<u32> m_snapshot_list;
    LittleEndian<u32> m_error_count;
    LittleEndian<u32> m_first_error_time;
    LittleEndian<u32> m_first_error_inode;
    LittleEndian<u64> m_first_error_block;
    Array<char, ERROR_FUNCTION_NAME_SIZE> m_first_error_function_name;
    LittleEndian<u32> m_first_error_line_number;
    LittleEndian<u32> m_last_error_time;
    LittleEndian<u32> m_last_error_inode;
    LittleEndian<u32> m_last_error_line_number;
    LittleEndian<u64> m_last_error_block;
    Array<char, ERROR_FUNCTION_NAME_SIZE> m_last_error_function_name;
    Array<char, MOUNT_OPTIONS_STRING_SIZE> m_mount_options_string;
    LittleEndian<u32> m_user_quota_inode_number;
    LittleEndian<u32> m_group_quota_inode_number;
    LittleEndian<u32> m_overhead_blocks;
    LittleEndian<u32> m_superblock_backup_group_1;
    LittleEndian<u32> m_superblock_backup_group_2;
    Array<u8, ENCRYPTION_ALGORITHM_COUNT> m_encryption_algorithms;
    Array<u8, ENCRYPTION_PASSWORD_SALT_SIZE> m_encryption_password_salt;
    LittleEndian<u32> m_lost_and_found_inode_number;
    LittleEndian<u32> m_project_quota_inode_number;
    LittleEndian<u32> m_checksum_seed;
    u8 _reserved[98 * 4];
    LittleEndian<u32> m_checksum;
};
static_assert(AssertSize<Superblock, 1024>());

}

namespace AK {

template<>
struct Traits<Ext4::Superblock> : public GenericTraits<Ext4::Superblock> {
    static constexpr bool is_trivially_serializable() { return true; }
};

}
