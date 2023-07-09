/*
 * Copyright (c) 2023, Tim Schumacher <timschumi@gmx.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Error.h>
#include <AK/MaybeOwned.h>
#include <AK/NonnullOwnPtr.h>
#include <AK/Stream.h>
#include <LibExt4/Superblock.h>

namespace Ext4 {

class Filesystem {
public:
    static ErrorOr<NonnullOwnPtr<Filesystem>> create(MaybeOwned<SeekableStream>);

    [[nodiscard]] Superblock const& superblock() const;

private:
    Filesystem(MaybeOwned<SeekableStream>, u64 stream_offset, Superblock);

    MaybeOwned<SeekableStream> m_stream;
    size_t m_stream_offset { 0 };

    Superblock m_superblock;
};

}
