# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
LOCAL_PATH := $(call my-dir)
ROOT_PATH := $(LOCAL_PATH)

BUILD_SHARED_EXECUTABLE := $(LOCAL_PATH)/build-shared-executable.mk

########################################################
## libsodium
########################################################

include $(CLEAR_VARS)

SODIUM_SOURCE := \
	crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c \
	crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c \
	crypto_auth/crypto_auth.c \
	crypto_auth/hmacsha256/auth_hmacsha256.c \
	crypto_auth/hmacsha512/auth_hmacsha512.c \
	crypto_auth/hmacsha512256/auth_hmacsha512256.c \
	crypto_box/crypto_box.c \
	crypto_box/crypto_box_easy.c \
	crypto_box/crypto_box_seal.c \
	crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c \
	crypto_core/ed25519/ref10/ed25519_ref10.c \
	crypto_core/hchacha20/core_hchacha20.c \
	crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c \
	crypto_core/hsalsa20/core_hsalsa20.c \
	crypto_core/salsa/ref/core_salsa_ref.c \
	crypto_generichash/crypto_generichash.c \
	crypto_generichash/blake2b/generichash_blake2.c \
	crypto_generichash/blake2b/ref/blake2b-compress-ref.c \
	crypto_generichash/blake2b/ref/blake2b-ref.c \
	crypto_generichash/blake2b/ref/generichash_blake2b.c \
	crypto_hash/crypto_hash.c \
	crypto_hash/sha256/hash_sha256.c \
	crypto_hash/sha256/cp/hash_sha256_cp.c \
	crypto_hash/sha512/hash_sha512.c \
	crypto_hash/sha512/cp/hash_sha512_cp.c \
	crypto_kdf/blake2b/kdf_blake2b.c \
	crypto_kdf/crypto_kdf.c \
	crypto_kx/crypto_kx.c \
	crypto_onetimeauth/crypto_onetimeauth.c \
	crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
	crypto_onetimeauth/poly1305/donna/poly1305_donna.c \
	crypto_pwhash/argon2/argon2-core.c \
	crypto_pwhash/argon2/argon2-encoding.c \
	crypto_pwhash/argon2/argon2-fill-block-ref.c \
	crypto_pwhash/argon2/argon2.c \
	crypto_pwhash/argon2/blake2b-long.c \
	crypto_pwhash/argon2/pwhash_argon2i.c \
	crypto_pwhash/argon2/pwhash_argon2id.c \
	crypto_pwhash/crypto_pwhash.c \
	crypto_scalarmult/crypto_scalarmult.c \
	crypto_scalarmult/curve25519/ref10/x25519_ref10.c \
	crypto_scalarmult/curve25519/scalarmult_curve25519.c \
	crypto_secretbox/crypto_secretbox.c \
	crypto_secretbox/crypto_secretbox_easy.c \
	crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c \
	crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c \
	crypto_shorthash/crypto_shorthash.c \
	crypto_shorthash/siphash24/shorthash_siphash24.c \
	crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c \
	crypto_sign/crypto_sign.c \
	crypto_sign/ed25519/sign_ed25519.c \
	crypto_sign/ed25519/ref10/keypair.c \
	crypto_sign/ed25519/ref10/open.c \
	crypto_sign/ed25519/ref10/sign.c \
	crypto_stream/chacha20/stream_chacha20.c \
	crypto_stream/chacha20/ref/chacha20_ref.c \
	crypto_stream/crypto_stream.c \
	crypto_stream/salsa20/stream_salsa20.c \
	crypto_stream/xsalsa20/stream_xsalsa20.c \
	crypto_verify/sodium/verify.c \
	randombytes/randombytes.c \
	sodium/codecs.c \
	sodium/core.c \
	sodium/runtime.c \
	sodium/utils.c \
	sodium/version.c \
	crypto_stream/salsa20/ref/salsa20_ref.c \
	crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c \
	crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c \
	crypto_core/ed25519/core_ed25519.c \
	crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c \
	crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c \
	crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c \
	crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c \
	crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c \
	crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c \
	crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c \
	crypto_shorthash/siphash24/shorthash_siphashx24.c \
	crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c \
	crypto_sign/ed25519/ref10/obsolete.c \
	crypto_stream/salsa2012/ref/stream_salsa2012_ref.c \
	crypto_stream/salsa2012/stream_salsa2012.c \
	crypto_stream/salsa208/ref/stream_salsa208_ref.c \
	crypto_stream/salsa208/stream_salsa208.c \
	crypto_stream/xchacha20/stream_xchacha20.c \
	randombytes/sysrandom/randombytes_sysrandom.c

SODIUM_DEFS := -DPACKAGE_NAME=\"libsodium\" -DPACKAGE_TARNAME=\"libsodium\" -DPACKAGE_VERSION=\"1.0.16\" -DPACKAGE_STRING=\"libsodium\ 1.0.16\" -DPACKAGE_BUGREPORT=\"https://github.com/jedisct1/libsodium/issues\" -DPACKAGE_URL=\"https://github.com/jedisct1/libsodium\" -DPACKAGE=\"libsodium\" -DVERSION=\"1.0.16\" -DHAVE_PTHREAD=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_C_VARARRAYS=1 -DTLS=_Thread_local -DHAVE_DLFCN_H=1 -DLT_OBJDIR=\".libs/\" -DHAVE_SYS_MMAN_H=1 -DNATIVE_LITTLE_ENDIAN=1 -DASM_HIDE_SYMBOL=.hidden -DHAVE_WEAK_SYMBOLS=1 -DHAVE_ATOMIC_OPS=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_BUF=1 -DHAVE_MMAP=1 -DHAVE_MLOCK=1 -DHAVE_MADVISE=1 -DHAVE_MPROTECT=1 -DHAVE_NANOSLEEP=1 -DHAVE_POSIX_MEMALIGN=1 -DHAVE_GETPID=1 -DCONFIGURED=1

SODIUM_DEFS += -DSODIUM_STATIC -DSODIUM_EXPORT=

LOCAL_MODULE := sodium
LOCAL_CFLAGS += -I$(LOCAL_PATH)/libsodium/src/libsodium/include \
				-I$(LOCAL_PATH)/include \
				-I$(LOCAL_PATH)/include/sodium \
				-I$(LOCAL_PATH)/libsodium/src/libsodium/include/sodium \
				$(SODIUM_DEFS)

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_SRC_FILES := $(addprefix libsodium/src/libsodium/,$(SODIUM_SOURCE))

include $(BUILD_STATIC_LIBRARY)

########################################################
## libevent
########################################################

include $(CLEAR_VARS)

LIBEVENT_SOURCES := \
	buffer.c				\
	bufferevent.c				\
	bufferevent_filter.c			\
	bufferevent_pair.c			\
	bufferevent_ratelim.c			\
	bufferevent_sock.c			\
	event.c					\
	evmap.c					\
	evthread.c				\
	evutil.c				\
	evutil_rand.c				\
	evutil_time.c				\
	listener.c				\
	log.c					\
	strlcpy.c \
	select.c  \
	poll.c    \
	devpoll.c \
	kqueue.c  \
	epoll.c   \
	evport.c  \
	signal.c  \
	evdns.c					\
	event_tagging.c				\
	evrpc.c					\
	http.c					\
	epoll_sub.c

LOCAL_MODULE := event
LOCAL_SRC_FILES := $(addprefix libevent/, $(LIBEVENT_SOURCES))
LOCAL_CFLAGS += \
	-I$(LOCAL_PATH)/libevent/compat \
	-I$(LOCAL_PATH)/libevent/include \
	-I$(LOCAL_PATH)/libevent

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

include $(BUILD_STATIC_LIBRARY)

########################################################
## libancillary
########################################################

include $(CLEAR_VARS)

ANCILLARY_SOURCE := fd_recv.c fd_send.c

LOCAL_MODULE := libancillary
LOCAL_CFLAGS += -I$(LOCAL_PATH)/libancillary

LOCAL_SRC_FILES := $(addprefix libancillary/, $(ANCILLARY_SOURCE))

include $(BUILD_STATIC_LIBRARY)

########################################################
## libipset
########################################################

include $(CLEAR_VARS)

bdd_src = bdd/assignments.c bdd/basics.c bdd/bdd-iterator.c bdd/expanded.c \
		  		  bdd/reachable.c bdd/read.c bdd/write.c
map_src = map/allocation.c map/inspection.c map/ipv4_map.c map/ipv6_map.c \
		  		  map/storage.c
set_src = set/allocation.c set/inspection.c set/ipv4_set.c set/ipv6_set.c \
		  		  set/iterator.c set/storage.c

IPSET_SOURCE := general.c $(bdd_src) $(map_src) $(set_src)

LOCAL_MODULE := libipset
LOCAL_CFLAGS += -I$(LOCAL_PATH)/shadowsocks-libev/libipset/include \
				-I$(LOCAL_PATH)/shadowsocks-libev/libcork/include

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_SRC_FILES := $(addprefix shadowsocks-libev/libipset/,$(IPSET_SOURCE))

include $(BUILD_STATIC_LIBRARY)

########################################################
## libcork
########################################################

include $(CLEAR_VARS)

cli_src := cli/commands.c
core_src := core/allocator.c core/error.c core/gc.c \
			core/hash.c core/ip-address.c core/mempool.c \
			core/timestamp.c core/u128.c
ds_src := ds/array.c ds/bitset.c ds/buffer.c ds/dllist.c \
		  ds/file-stream.c ds/hash-table.c ds/managed-buffer.c \
		  ds/ring-buffer.c ds/slice.c
posix_src := posix/directory-walker.c posix/env.c posix/exec.c \
			 posix/files.c posix/process.c posix/subprocess.c
pthreads_src := pthreads/thread.c

CORK_SOURCE := $(cli_src) $(core_src) $(ds_src) $(posix_src) $(pthreads_src)

LOCAL_MODULE := libcork
LOCAL_CFLAGS += -I$(LOCAL_PATH)/shadowsocks-libev/libcork/include \
				-DCORK_API=CORK_LOCAL

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_SRC_FILES := $(addprefix shadowsocks-libev/libcork/,$(CORK_SOURCE))

include $(BUILD_STATIC_LIBRARY)

########################################################
## libcares
########################################################

include $(CLEAR_VARS)

CARES_SOURCES := ares__close_sockets.c	\
  ares__get_hostent.c			\
  ares__read_line.c			\
  ares__timeval.c			\
  ares_android.c				\
  ares_cancel.c				\
  ares_data.c				\
  ares_destroy.c			\
  ares_expand_name.c			\
  ares_expand_string.c			\
  ares_fds.c				\
  ares_free_hostent.c			\
  ares_free_string.c			\
  ares_getenv.c				\
  ares_gethostbyaddr.c			\
  ares_gethostbyname.c			\
  ares_getnameinfo.c			\
  ares_getsock.c			\
  ares_init.c				\
  ares_library_init.c			\
  ares_llist.c				\
  ares_mkquery.c			\
  ares_create_query.c			\
  ares_nowarn.c				\
  ares_options.c			\
  ares_parse_a_reply.c			\
  ares_parse_aaaa_reply.c		\
  ares_parse_mx_reply.c			\
  ares_parse_naptr_reply.c		\
  ares_parse_ns_reply.c			\
  ares_parse_ptr_reply.c		\
  ares_parse_soa_reply.c		\
  ares_parse_srv_reply.c		\
  ares_parse_txt_reply.c		\
  ares_platform.c			\
  ares_process.c			\
  ares_query.c				\
  ares_search.c				\
  ares_send.c				\
  ares_strcasecmp.c			\
  ares_strdup.c				\
  ares_strerror.c			\
  ares_timeout.c			\
  ares_version.c			\
  ares_writev.c				\
  bitncmp.c				\
  inet_net_pton.c			\
  inet_ntop.c				\
  windows_port.c

LOCAL_MODULE := libcares
LOCAL_CFLAGS += -I$(LOCAL_PATH)/shadowsocks-libev/libcares \
	-I$(LOCAL_PATH)/include/libcares \
	-DCARES_BUILDING_LIBRARY -DCARES_STATICLIB \
	-DHAVE_CONFIG_H

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_SRC_FILES := $(addprefix shadowsocks-libev/libcares/,$(CARES_SOURCES))

include $(BUILD_STATIC_LIBRARY)

########################################################
## libev
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := libev
LOCAL_CFLAGS += -DNDEBUG -DHAVE_CONFIG_H \
				-I$(LOCAL_PATH)/include/libev
LOCAL_SRC_FILES := \
	shadowsocks-libev/libev/ev.c \
	shadowsocks-libev/libev/event.c

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

include $(BUILD_STATIC_LIBRARY)

########################################################
## redsocks
########################################################

include $(CLEAR_VARS)

REDSOCKS_SOURCES := base.c http-connect.c \
	log.c md5.c socks5.c \
	base64.c http-auth.c http-relay.c main.c \
	parser.c redsocks.c socks4.c utils.c

LOCAL_STATIC_LIBRARIES := libevent

LOCAL_MODULE := redsocks
LOCAL_SRC_FILES := $(addprefix redsocks/, $(REDSOCKS_SOURCES)) 
LOCAL_CFLAGS += -std=gnu99 -DUSE_IPTABLES \
	-D_GNU_SOURCE \
	-I$(LOCAL_PATH)/redsocks \
	-I$(LOCAL_PATH)/libevent/include \
	-I$(LOCAL_PATH)/libevent

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

include $(BUILD_SHARED_EXECUTABLE)

########################################################
## shadowsocks-libev local
########################################################

include $(CLEAR_VARS)

SHADOWSOCKS_SOURCES := local.c \
	cache.c udprelay.c utils.c netutils.c json.c jconf.c \
	acl.c http.c tls.c rule.c \
	crypto.c aead.c stream.c \
	sbf.c \
	android.c

LOCAL_MODULE    := ss-local
LOCAL_SRC_FILES := $(addprefix shadowsocks-libev/src/, $(SHADOWSOCKS_SOURCES))
LOCAL_CFLAGS    += -Wall -fno-strict-aliasing -DMODULE_LOCAL \
					-DUSE_CRYPTO_MBEDTLS -DHAVE_CONFIG_H \
					-DCONNECT_IN_PROGRESS=EINPROGRESS \
					-DHAVE_POSIX_MEMALIGN=1 \
					-DHAVE_LINUX_RANDOM_H=1 \
					-DHAVE_LINUX_TCP_H=1 \
					-DHAVE_NETINET_TCP_H=1 \
					-DHAVE_NETDB_H=1 \
					-I$(LOCAL_PATH)/include/shadowsocks-libev \
					-I$(LOCAL_PATH)/include/libcares \
					-I$(LOCAL_PATH)/include \
					-I$(LOCAL_PATH)/libancillary \
					-I$(LOCAL_PATH)/mbedtls/include  \
					-I$(LOCAL_PATH)/pcre/include \
					-I$(LOCAL_PATH)/shadowsocks-libev/libcares \
					-I$(LOCAL_PATH)/libsodium/src/libsodium/include \
					-I$(LOCAL_PATH)/libsodium/src/libsodium/include/sodium \
					-I$(LOCAL_PATH)/shadowsocks-libev/libcork/include \
					-I$(LOCAL_PATH)/shadowsocks-libev/libipset/include \
					-I$(LOCAL_PATH)/libev

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_STATIC_LIBRARIES := libev libmbedtls libipset libcork libcares \
	libsodium libancillary libpcre2

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_EXECUTABLE)

########################################################
## shadowsocks-libev tunnel
########################################################

include $(CLEAR_VARS)

SHADOWSOCKS_SOURCES := tunnel.c \
	cache.c udprelay.c utils.c netutils.c json.c jconf.c \
	crypto.c aead.c stream.c \
	sbf.c \
	android.c

LOCAL_MODULE    := ss-tunnel
LOCAL_SRC_FILES := $(addprefix shadowsocks-libev/src/, $(SHADOWSOCKS_SOURCES))
LOCAL_CFLAGS    += -Wall -fno-strict-aliasing -DMODULE_TUNNEL \
					-DUSE_CRYPTO_MBEDTLS -DHAVE_CONFIG_H -DSSTUNNEL_JNI \
					-DCONNECT_IN_PROGRESS=EINPROGRESS \
					-DHAVE_POSIX_MEMALIGN=1 \
					-DHAVE_LINUX_RANDOM_H=1 \
					-DHAVE_LINUX_TCP_H=1 \
					-DHAVE_NETINET_TCP_H=1 \
					-DHAVE_NETDB_H=1 \
					-I$(LOCAL_PATH)/libancillary \
					-I$(LOCAL_PATH)/include \
					-I$(LOCAL_PATH)/shadowsocks-libev/libcares \
					-I$(LOCAL_PATH)/libsodium/src/libsodium/include \
					-I$(LOCAL_PATH)/libsodium/src/libsodium/include/sodium \
					-I$(LOCAL_PATH)/mbedtls/include \
					-I$(LOCAL_PATH)/libev \
					-I$(LOCAL_PATH)/shadowsocks-libev/libcork/include \
					-I$(LOCAL_PATH)/include/shadowsocks-libev \
					-I$(LOCAL_PATH)/include/libcares

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_STATIC_LIBRARIES := libev libmbedtls libsodium libcork libcares libancillary

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_EXECUTABLE)

########################################################
## jni-helper
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE:= jni-helper

LOCAL_CFLAGS := -std=c++11

LOCAL_C_INCLUDES:= $(LOCAL_PATH)/libancillary

LOCAL_SRC_FILES:= jni-helper.cpp

LOCAL_LDLIBS := -ldl -llog

LOCAL_STATIC_LIBRARIES := cpufeatures libancillary

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

include $(BUILD_SHARED_LIBRARY)

########################################################
## tun2socks
########################################################

include $(CLEAR_VARS)

LOCAL_CFLAGS := -std=gnu99
LOCAL_CFLAGS += -DBADVPN_THREADWORK_USE_PTHREAD -DBADVPN_THREAD_SAFE=1 -DBADVPN_LINUX -DBADVPN_BREACTOR_BADVPN -D_GNU_SOURCE
LOCAL_CFLAGS += -DBADVPN_USE_SIGNALFD -DBADVPN_USE_EPOLL
LOCAL_CFLAGS += -DBADVPN_LITTLE_ENDIAN
LOCAL_CFLAGS += -DNDEBUG -DANDROID
LOCAL_CFLAGS += -Wno-parentheses -Wno-gnu-designator
# LOCAL_CFLAGS += -DTUN2SOCKS_JNI

LOCAL_STATIC_LIBRARIES := libancillary

LOCAL_C_INCLUDES:= \
		$(LOCAL_PATH)/libancillary \
        $(LOCAL_PATH)/badvpn/lwip/src/include/ipv4 \
        $(LOCAL_PATH)/badvpn/lwip/src/include/ipv6 \
        $(LOCAL_PATH)/badvpn/lwip/src/include \
        $(LOCAL_PATH)/badvpn/lwip/custom \
        $(LOCAL_PATH)/badvpn/

TUN2SOCKS_SOURCES := \
	base/BLog_syslog.c                        \
	system/BReactor_badvpn.c                  \
	system/BSignal.c                          \
	system/BConnection_unix.c                 \
	system/BConnection_common.c               \
	system/BTime.c                            \
	system/BUnixSignal.c                      \
	system/BNetwork.c                         \
	system/BDatagram_unix.c                   \
	flow/StreamRecvInterface.c                \
	flow/PacketRecvInterface.c                \
	flow/PacketPassInterface.c                \
	flow/StreamPassInterface.c                \
	flow/SinglePacketBuffer.c                 \
	flow/BufferWriter.c                       \
	flow/PacketBuffer.c                       \
	flow/PacketStreamSender.c                 \
	flow/PacketPassConnector.c                \
	flow/PacketProtoFlow.c                    \
	flow/PacketPassFairQueue.c                \
	flow/PacketProtoEncoder.c                 \
	flow/PacketProtoDecoder.c                 \
	socksclient/BSocksClient.c                \
	tuntap/BTap.c                             \
	lwip/src/core/init.c \
	lwip/src/core/def.c \
	lwip/src/core/dns.c \
	lwip/src/core/inet_chksum.c \
	lwip/src/core/ip.c \
	lwip/src/core/mem.c \
	lwip/src/core/memp.c \
	lwip/src/core/netif.c \
	lwip/src/core/pbuf.c \
	lwip/src/core/raw.c \
	lwip/src/core/stats.c \
	lwip/src/core/sys.c \
	lwip/src/core/altcp.c \
	lwip/src/core/altcp_tcp.c \
	lwip/src/core/tcp.c \
	lwip/src/core/tcp_in.c \
	lwip/src/core/tcp_out.c \
	lwip/src/core/timeouts.c \
	lwip/src/core/udp.c \
	lwip/src/core/ipv4/autoip.c \
	lwip/src/core/ipv4/dhcp.c \
	lwip/src/core/ipv4/etharp.c \
	lwip/src/core/ipv4/icmp.c \
	lwip/src/core/ipv4/igmp.c \
	lwip/src/core/ipv4/ip4_frag.c \
	lwip/src/core/ipv4/ip4.c \
	lwip/src/core/ipv4/ip4_addr.c \
	lwip/src/core/ipv6/dhcp6.c \
	lwip/src/core/ipv6/ethip6.c \
	lwip/src/core/ipv6/icmp6.c \
	lwip/src/core/ipv6/inet6.c \
	lwip/src/core/ipv6/ip6.c \
	lwip/src/core/ipv6/ip6_addr.c \
	lwip/src/core/ipv6/ip6_frag.c \
	lwip/src/core/ipv6/mld6.c \
	lwip/src/core/ipv6/nd6.c \
	lwip/custom/sys.c                         \
	tun2socks/tun2socks.c                     \
	base/DebugObject.c                        \
	base/BLog.c                               \
	base/BPending.c                           \
	flowextra/PacketPassInactivityMonitor.c   \
	tun2socks/SocksUdpGwClient.c              \
	udpgw_client/UdpGwClient.c

LOCAL_MODULE := tun2socks

LOCAL_LDLIBS := -ldl -llog

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

LOCAL_SRC_FILES := $(addprefix badvpn/, $(TUN2SOCKS_SOURCES))

include $(BUILD_SHARED_EXECUTABLE)

########################################################
## mbed TLS
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := mbedtls

LOCAL_C_INCLUDES := $(LOCAL_PATH)/mbedtls/include

MBEDTLS_SOURCES := $(wildcard $(LOCAL_PATH)/mbedtls/library/*.c)

LOCAL_SRC_FILES := $(MBEDTLS_SOURCES:$(LOCAL_PATH)/%=%)

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

include $(BUILD_STATIC_LIBRARY)

########################################################
## pcre2
########################################################

include $(CLEAR_VARS)

LOCAL_MODULE := pcre2

LOCAL_CFLAGS += -DHAVE_CONFIG_H

LOCAL_C_INCLUDES := $(LOCAL_PATH)/pcre/include_internal $(LOCAL_PATH)/pcre/include

libpcre2_src_files := \
    dist2/src/pcre2_auto_possess.c  \
    dist2/src/pcre2_compile.c       \
    dist2/src/pcre2_config.c        \
    dist2/src/pcre2_context.c       \
    dist2/src/pcre2_dfa_match.c     \
    dist2/src/pcre2_error.c         \
    dist2/src/pcre2_find_bracket.c  \
    dist2/src/pcre2_maketables.c    \
    dist2/src/pcre2_match.c         \
    dist2/src/pcre2_match_data.c    \
    dist2/src/pcre2_jit_compile.c   \
    dist2/src/pcre2_newline.c       \
    dist2/src/pcre2_ord2utf.c       \
    dist2/src/pcre2_pattern_info.c  \
    dist2/src/pcre2_serialize.c     \
    dist2/src/pcre2_string_utils.c  \
    dist2/src/pcre2_study.c         \
    dist2/src/pcre2_substitute.c    \
    dist2/src/pcre2_substring.c     \
    dist2/src/pcre2_tables.c        \
    dist2/src/pcre2_ucd.c           \
    dist2/src/pcre2_valid_utf.c     \
    dist2/src/pcre2_xclass.c        \
    dist2/src/pcre2_chartables.c

LOCAL_SRC_FILES := $(addprefix pcre/, $(libpcre2_src_files))

# No need to add '-Wl,' prefix to LDFLAGS
# Gold does not support mips or mips64, but gold is needed for LTO with Clang.
ifeq (,$(filter $(TARGET_ARCH_ABI),mips mips64 x86))
    LOCAL_CFLAGS += -flto
    LOCAL_LDFLAGS := -flto -fuse-ld=gold
endif

include $(BUILD_STATIC_LIBRARY)

# Import cpufeatures
$(call import-module,android/cpufeatures)

