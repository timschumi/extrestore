set(SOURCES
    extdump.cpp
)

serenity_bin(extdump)
target_link_libraries(extdump PRIVATE LibCore LibExt4 LibMain)
