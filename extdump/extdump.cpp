/*
 * Copyright (c) 2023, Tim Schumacher <timschumi@gmx.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/ArgsParser.h>
#include <LibCore/File.h>
#include <LibExt4/Superblock.h>

ErrorOr<int> serenity_main(Main::Arguments arguments)
{
    StringView filename;

    Core::ArgsParser args;
    args.add_positional_argument(filename, "File to dump", "file", Core::ArgsParser::Required::Yes);
    args.parse(arguments);

    auto file = TRY(Core::File::open(filename, Core::File::OpenMode::Read));

    // ext4 keeps the first 1024 bytes empty to allow for x86 boot sectors and other things. The superblock doesn't start until after that.
    constexpr size_t ext4_group_zero_padding = 1024;

    if (TRY(file->size()) < ext4_group_zero_padding + sizeof(Ext4::Superblock))
        return Error::from_string_view("File does not contain enough data for a full superblock"sv);

    // Discard the empty space and read the superblock.
    TRY(file->discard(ext4_group_zero_padding));
    auto superblock = TRY(file->read_value<Ext4::Superblock>());

    TRY(superblock.validate());

    auto compatible_feature_set = superblock.compatible_feature_set();
    auto incompatible_feature_set = superblock.incompatible_feature_set();
    auto read_only_feature_set = superblock.read_only_feature_set();

    outln("Superblock:");
    outln("  Total inode count:                {}", superblock.inode_count());
    outln("  Total block count:                {}", superblock.block_count());
    outln("  Reserved block count:             {}", superblock.reserved_block_count());
    outln("  Free block count:                 {}", superblock.free_block_count());
    outln("  Free inode count:                 {}", superblock.free_inode_count());
    outln("  First data block:                 {}", superblock.first_data_block());
    outln("  Block size:                       {}", superblock.block_size());
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::BigAlloc))
        outln("  Cluster size:                     {}", superblock.cluster_size());
    outln("  Blocks per group:                 {}", superblock.blocks_per_group());
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::BigAlloc))
        outln("  Clusters per group:               {}", superblock.clusters_per_group());
    outln("  Inodes per group:                 {}", superblock.inodes_per_group());
    outln("  Mount time:                       {}", superblock.mount_time().seconds_since_epoch());
    outln("  Write time:                       {}", superblock.write_time().seconds_since_epoch());
    outln("  Mounts since last fsck:           {}", superblock.mounts_since_last_fsck());
    outln("  Maximum mounts since last fsck:   {}", superblock.maximum_mounts_since_last_fsck());

    auto file_system_state = superblock.file_system_state();
    outln("  File system state:");
    if (has_flag(file_system_state, Ext4::FileSystemState::CleanlyUnmounted))
        outln("   - Cleanly unmounted");
    if (has_flag(file_system_state, Ext4::FileSystemState::ErrorsDetected))
        outln("   - Errors detected");
    if (has_flag(file_system_state, Ext4::FileSystemState::OrphansBeingRecovered))
        outln("   - Orphans being recovered");

    auto error_detection_behavior = superblock.error_detection_behavior();
    out("  Error detection behavior:         ");
    switch (error_detection_behavior) {
    case Ext4::ErrorDetectionBehavior::Continue:
        outln("Continue");
        break;
    case Ext4::ErrorDetectionBehavior::ReadOnly:
        outln("Read-Only");
        break;
    case Ext4::ErrorDetectionBehavior::Panic:
        outln("Panic");
        break;
    default:
        outln("Unknown");
        break;
    }

    outln("  Minor revision level:             {}", superblock.minor_revision_level());
    outln("  Last check time:                  {}", superblock.last_check_time().seconds_since_epoch());
    outln("  Maximum last check interval:      {}", superblock.maximum_last_check_interval().to_seconds());

    auto creator_os = superblock.creator_os();
    out("  Creator Operating System:         ");
    switch (creator_os) {
    case Ext4::CreatorOS::Linux:
        outln("Linux");
        break;
    case Ext4::CreatorOS::Hurd:
        outln("Hurd");
        break;
    case Ext4::CreatorOS::Masix:
        outln("Masix");
        break;
    case Ext4::CreatorOS::FreeBSD:
        outln("FreeBSD");
        break;
    case Ext4::CreatorOS::Lites:
        outln("Lites");
        break;
    default:
        outln("Unknown");
        break;
    }

    auto revision_level = superblock.revision_level();
    out("  Revision level:                   ");
    switch (revision_level) {
    case Ext4::RevisionLevel::Original:
        outln("Original");
        break;
    case Ext4::RevisionLevel::V2:
        outln("V2");
        break;
    default:
        outln("Unknown");
        break;
    }

    outln("  Default reserved block UID:       {}", superblock.reserved_blocks_default_uid());
    outln("  Default reserved block GID:       {}", superblock.reserved_blocks_default_gid());
    outln("  First inode:                      {}", superblock.first_inode());
    outln("  Inode size:                       {}", superblock.inode_size());
    outln("  Block group number:               {}", superblock.block_group_number());

    outln("  Compatible feature set:");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::DirectoryPreallocation))
        outln("   - Directory preallocation");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::ImagicInodes))
        outln("   - Imagic inodes");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::Journal))
        outln("   - Journal");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::ExtendedAttributes))
        outln("   - Extended attributes");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::ReservedGDTBlocks))
        outln("   - Reserved GDT blocks");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::IndexedDirectories))
        outln("   - Indexed directories");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::LazyBG))
        outln("   - Lazy BG");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::ExcludeInode))
        outln("   - Exclude inode");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::ExcludeBitmap))
        outln("   - Exclude bitmap");
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::SparseSuperBlockV2))
        outln("   - Sparse superblock, v2");

    outln("  Incompatible feature set:");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::Compression))
        outln("   - Compression");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::DirectoryEntryFileType))
        outln("   - Directory entry file types");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::JournalRecovery))
        outln("   - Journal recovery");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::JournalDevice))
        outln("   - Separate journal device");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::MetaBlockGroups))
        outln("   - Meta block groups");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::Extents))
        outln("   - Extents");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::SixtyFourBits))
        outln("   - 64bit");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::MultipleMountProtection))
        outln("   - Multiple mount protection");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::FlexibleBlockGroups))
        outln("   - Flexible block groups");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::LargeExtendedAttributes))
        outln("   - Large extended attributes");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::DirectoryEntryDataField))
        outln("   - Data in directory entry");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::ChecksumSeed))
        outln("   - Metadata checsum seed");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::LargeDirectories))
        outln("   - Large directories");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::InlineData))
        outln("   - Inline inode data");
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::EncryptedInodes))
        outln("   - Encrypted inodes");

    outln("  Read-Only feature set:");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::SparseSuperblocks))
        outln("   - Sparse superblocks");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::LargeFiles))
        outln("   - Large files");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::HugeFiles))
        outln("   - Huge files");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::GroupDescriptorChecksums))
        outln("   - Group descriptor checksums");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::NoLinkLimit))
        outln("   - No link limit");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::LargeInodes))
        outln("   - Large inodes");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::Snapshots))
        outln("   - Snapshots");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::Quota))
        outln("   - Quotas");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::BigAlloc))
        outln("   - bigalloc");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::MetadataChecksum))
        outln("   - Metadata checksums");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::Replicas))
        outln("   - Replicas");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::ReadOnly))
        outln("   - Read-Only");
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::ProjectQuotas))
        outln("   - ProjectQuotas");

    outln("  UUID:                             {}", TRY(superblock.uuid().to_string()));
    outln("  Volume label:                     {}", superblock.volume_label());
    outln("  Last mounted path:                {}", superblock.last_mounted_path());
    outln("  Algorithm usage bitmap:           {:b}", superblock.algorithm_usage_bitmap());
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::DirectoryPreallocation)) {
        outln("  Preallocated file blocks:         {}", superblock.preallocated_file_blocks());
        outln("  Preallocated directory blocks:    {}", superblock.preallocated_directory_blocks());
    }
    outln("  Reserved GDT blocks:              {}", superblock.reserved_gdt_blocks());
    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::Journal)) {
        outln("  Journal superblock UUID:          {}", TRY(superblock.journal_superblock_uuid().to_string()));
        outln("  Journal inode number:             {}", superblock.journal_inode_number());
        if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::JournalDevice))
            outln("  Journal device number:            {}", superblock.journal_device_number());
    }
    outln("  Last orphan:                      {}", superblock.last_orphan());

    auto default_directory_hash_algorithm = superblock.default_directory_hash_algorithm();
    out("  Default directory hash algorithm: ");
    switch (default_directory_hash_algorithm) {
    case Ext4::HashAlgorithm::Legacy:
        outln("Legacy");
        break;
    case Ext4::HashAlgorithm::HalfMD4:
        outln("Half-MD4");
        break;
    case Ext4::HashAlgorithm::Tea:
        outln("Tea");
        break;
    case Ext4::HashAlgorithm::LegacyUnsigned:
        outln("Legacy (unsigned)");
        break;
    case Ext4::HashAlgorithm::HalfMD4Unsigned:
        outln("Half-MD4 (unsigned)");
        break;
    case Ext4::HashAlgorithm::TeaUnsigned:
        outln("Tea (unsigned)");
        break;
    default:
        outln("Unknown");
        break;
    }

    // TODO: Figure out the values for journal_backup_type.
    outln("  Group descriptor size:            {}", superblock.group_descriptor_size());

    auto default_mount_options = superblock.default_mount_options();
    outln("  Default mount options:");
    if (has_flag(default_mount_options, Ext4::MountOption::Debug))
        outln("   - Debug");
    if (has_flag(default_mount_options, Ext4::MountOption::InheritGroupFromDirectory))
        outln("   - Inherit group from directory");
    if (has_flag(default_mount_options, Ext4::MountOption::UserspaceExtendedAttributes))
        outln("   - Userspace extended attributes");
    if (has_flag(default_mount_options, Ext4::MountOption::AccessControlLists))
        outln("   - Access control lists");
    if (has_flag(default_mount_options, Ext4::MountOption::Only16BitUID))
        outln("   - 16-bit UIDs");
    if (has_flag(default_mount_options, Ext4::MountOption::JournalData))
        outln("   - Commit data to journal");
    if (has_flag(default_mount_options, Ext4::MountOption::JournalOrdered))
        outln("   - Flush data to disk before committing metadata to journal");
    if (has_flag(default_mount_options, Ext4::MountOption::NoBarrier))
        outln("   - Disable write flushes");
    if (has_flag(default_mount_options, Ext4::MountOption::TrackMetadataBlocks))
        outln("   - Track metadata blocks");
    if (has_flag(default_mount_options, Ext4::MountOption::Discard))
        outln("   - DISCARD support");
    if (has_flag(default_mount_options, Ext4::MountOption::DisableDelayedAllocation))
        outln("   - Disable delayed allocation");

    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::MetaBlockGroups))
        outln("  First metatable block group:      {}", superblock.first_meta_block_group());
    outln("  Creation time:                    {}", superblock.creation_time().seconds_since_epoch());
    outln("  Minimum extra inode size:         {}", superblock.minimum_extra_inode_size());
    outln("  Wanted extra inode size:          {}", superblock.wanted_extra_inode_size());

    auto flags = superblock.flags();
    outln("  Flags:");
    if (has_flag(flags, Ext4::Flags::UsingSignedDirectoryHash))
        outln("   - Signed directory hash");
    if (has_flag(flags, Ext4::Flags::UsingUnsignedDirectoryHash))
        outln("   - Unsigned directory hash");
    if (has_flag(flags, Ext4::Flags::TestDevelopmentCode))
        outln("   - Test development code");

    outln("  RAID stride blocks:               {}", superblock.raid_stride_blocks());
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::MultipleMountProtection)) {
        outln("  Multi mount protection interval:  {}", superblock.multi_mount_protection_interval());
        outln("  Multi mount protection block:     {}", superblock.multi_mount_protection_block());
    }
    outln("  RAID stripe width:                {}", superblock.raid_stripe_width());
    outln("  Flexible block group size:        {}", superblock.flexible_block_group_size());
    outln("  Written kibibytes:                {}", superblock.written_kibibytes());
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::Snapshots)) {
        outln("  Active snapshot inode:            {}", superblock.active_snapshot_inode());
        outln("  Active snapshot id:               {}", superblock.active_snapshot_id());
        outln("  Active snapshot reserved blocks:  {}", superblock.active_snapshot_reserved_blocks());
        outln("  Snapshot list:                    {}", superblock.snapshot_list());
    }
    outln("  Error count:                      {}", superblock.error_count());
    outln("  First error time:                 {}", superblock.first_error_time().seconds_since_epoch());
    outln("  First error inode:                {}", superblock.first_error_inode());
    outln("  First error block:                {}", superblock.first_error_block());
    outln("  First error function name:        {}", superblock.first_error_function_name());
    outln("  First error line number:          {}", superblock.first_error_line_number());
    outln("  Last error time:                  {}", superblock.last_error_time().seconds_since_epoch());
    outln("  Last error inode:                 {}", superblock.last_error_inode());
    outln("  Last error line number:           {}", superblock.last_error_line_number());
    outln("  Last error block:                 {}", superblock.last_error_block());
    outln("  Last error function name:         {}", superblock.last_error_function_name());
    outln("  Mount options string:             {}", superblock.mount_options_string());
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::Quota)) {
        outln("  User quota inode number:          {}", superblock.user_quota_inode_number());
        outln("  Group quota inode number:         {}", superblock.group_quota_inode_number());
    }
    outln("  Overhead blocks:                  {}", superblock.overhead_blocks());

    if (has_flag(compatible_feature_set, Ext4::CompatibleFeatureSet::SparseSuperBlockV2)) {
        auto superblock_backup_groups = superblock.superblock_backup_groups();
        outln("  Superblock backup groups:         {}, {}", superblock_backup_groups[0], superblock_backup_groups[1]);
    }

    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::EncryptedInodes)) {
        auto encryption_algorithms = superblock.encryption_algorithms();
        outln("  Encryption algorithms:");
        for (auto encryption_algorithm : encryption_algorithms) {
            switch (encryption_algorithm) {
            case Ext4::EncryptionAlgorithm::Invalid:
                outln("   - Invalid");
                break;
            case Ext4::EncryptionAlgorithm::AES256XTS:
                outln("   - AES-256-XTS");
                break;
            case Ext4::EncryptionAlgorithm::AES256GCM:
                outln("   - AES-256-GCM");
                break;
            case Ext4::EncryptionAlgorithm::AES256CBC:
                outln("   - AES-256-CBC");
                break;
            default:
                outln("   - Unknown");
                break;
            }
        }

        outln("  Encryption password salt:         {}", superblock.encryption_password_salt());
    }

    outln("  lost+found inode number:          {}", superblock.lost_and_found_inode_number());
    if (has_flag(read_only_feature_set, Ext4::ReadOnlyFeatureSet::ProjectQuotas)) {
        outln("  Project quota inode number:       {}", superblock.project_quota_inode_number());
    }
    if (has_flag(incompatible_feature_set, Ext4::IncompatibleFeatureSet::ChecksumSeed)) {
        outln("  Checksum seed:                    {}", superblock.checksum_seed());
    }
    outln("  Checksum:                         {}", superblock.checksum());

    return 0;
}
