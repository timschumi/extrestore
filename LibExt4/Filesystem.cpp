/*
 * Copyright (c) 2023, Tim Schumacher <timschumi@gmx.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibExt4/Filesystem.h>

namespace Ext4 {

ErrorOr<NonnullOwnPtr<Filesystem>> Filesystem::create(MaybeOwned<AK::SeekableStream> stream)
{
    // Record the starting offset to seek to the correct positions later.
    auto stream_offset = TRY(stream->tell());

    // ext4 keeps the first 1024 bytes empty to allow for x86 boot sectors and other things. The superblock doesn't start until after that.
    constexpr size_t ext4_group_zero_padding = 1024;

    // Discard the empty space and read the superblock.
    TRY(stream->discard(ext4_group_zero_padding));
    auto superblock = TRY(stream->read_value<Ext4::Superblock>());

    TRY(superblock.validate());

    return adopt_nonnull_own_or_enomem(new (nothrow) Filesystem(move(stream), stream_offset, superblock));
}

Filesystem::Filesystem(MaybeOwned<AK::SeekableStream> stream, u64 stream_offset, Ext4::Superblock superblock)
    : m_stream(move(stream))
    , m_stream_offset(stream_offset)
    , m_superblock(superblock)
{
}

Superblock const& Filesystem::superblock() const
{
    return m_superblock;
}

}
