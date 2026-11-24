/* r2renef - MIT - Copyright 2025-2026 */

/*
 * Unit tests for src/renef_proto.c: reply parsers, the framing reader and
 * the small encoders. No radare2, no network.
 *
 * Inputs handed to the parsers are copied into exactly sized heap blocks
 * without a terminator, so building with -fsanitize=address turns any
 * read past the end of a reply into a failure.
 */

#include "../src/renef_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
static int g_failed = 0;

#define CHECK(cond) do { \
	g_checks++; \
	if (!(cond)) { \
		g_failed++; \
		fprintf (stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

/* exactly sized, unterminated copy */
static char *exact(const char *s, size_t n) {
	char *p = malloc (n? n: 1);
	memcpy (p, s, n);
	return p;
}

static int md(const char *text, uint64_t addr, uint8_t *out, int max) {
	size_t n = strlen (text);
	char *p = exact (text, n);
	int r = rn_parse_md (p, n, addr, out, max);
	free (p);
	return r;
}

/* ---- md dump parser ---- */

static void test_md_basic(void) {
	/* the sample the old tests/cmd_md_parser.c printed */
	static const char dump[] =
		"0x78b5491060:  ff ff ff ff ff 44 0e 30 48 0c 1d 10 9e 02 9d 04  |.....D.0H.......|\n"
		"0x78b5491070:  0a 02 78 0c 1f 30 48 0e 00 de dd 44 0b 00 00 00  |..x..0H....D....|\n"
		"0x78b5491080:  30 00 00 00 5c 0e 00 00 bc b8 01 00 d4 00 00 00  |0...............|\n"
		"0x78b5491090:  08 6b 92 fc ff ff ff ff ff 44 0e 80 01 48 0c 1d  |.k.......D...H..|\n";
	static const uint8_t want[64] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0x44, 0x0e, 0x30, 0x48, 0x0c, 0x1d, 0x10, 0x9e, 0x02, 0x9d, 0x04,
		0x0a, 0x02, 0x78, 0x0c, 0x1f, 0x30, 0x48, 0x0e, 0x00, 0xde, 0xdd, 0x44, 0x0b, 0x00, 0x00, 0x00,
		0x30, 0x00, 0x00, 0x00, 0x5c, 0x0e, 0x00, 0x00, 0xbc, 0xb8, 0x01, 0x00, 0xd4, 0x00, 0x00, 0x00,
		0x08, 0x6b, 0x92, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0x44, 0x0e, 0x80, 0x01, 0x48, 0x0c, 0x1d,
	};
	uint8_t out[256];
	CHECK (md (dump, 0x78b5491060ULL, out, sizeof (out)) == 64);
	CHECK (!memcmp (out, want, 64));
	/* the caller's limit is honoured */
	memset (out, 0xee, sizeof (out));
	CHECK (md (dump, 0x78b5491060ULL, out, 20) == 20);
	CHECK (out[19] == 0x0c && out[20] == 0xee);
	/* a dump of some other address is not an answer */
	CHECK (md (dump, 0x78b5491070ULL, out, sizeof (out)) == 48);
	CHECK (md (dump, 0x1000, out, sizeof (out)) == -1);
}

static void test_md_header_and_partial_line(void) {
	static const char dump[] =
		"Memory at 0x7000000000 (19 bytes):\n"
		"0x7000000000:  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  |.ELF............|\n"
		"0x7000000010:  03 00 b7                                         |...|\n";
	uint8_t out[64];
	CHECK (md (dump, 0x7000000000ULL, out, sizeof (out)) == 19);
	CHECK (out[0] == 0x7f && out[3] == 0x46 && out[16] == 0x03 && out[18] == 0xb7);
	/* header for another address: stale reply */
	CHECK (md (dump, 0x7000000010ULL, out, sizeof (out)) == 3);
	CHECK (md ("Memory at 0x10 (4 bytes):\n0x00000010:  01 02 03 04  |....|\n", 0x20, out, sizeof (out)) == -1);
}

static void test_md_ascii_column(void) {
	/* the ASCII column may hold '|', ':' and things that look like hex */
	static const char dump[] =
		"0x00001000:  7c 7c 3a 61 62 20 63 64 30 78 31 32 3a 20 66 66  |||:ab cd0x12: ff|\n"
		"0x00001010:  41 42                                            |AB|\n";
	uint8_t out[64];
	CHECK (md (dump, 0x1000, out, sizeof (out)) == 18);
	CHECK (out[0] == 0x7c && out[15] == 0x66 && out[16] == 0x41 && out[17] == 0x42);
}

static void test_md_malformed(void) {
	uint8_t out[64];
	/* every one of these ends in the middle of something; none may be
	 * read past its last byte (ASan) and none yields a byte that is not
	 * fully there */
	static const char *const cases[] = {
		"0x00001000:  7f 4",
		"0x00001000:  7f 45 4",
		"0x00001000:  7",
		"0x00001000:  ",
		"0x00001000:",
		"0x00001000",
		"0x",
		"0",
		"",
		"0x00001000:  zz 01 02",
		"0x00001000:  7f4 5 ",
		"0x00001000:  7f\n",
		"0x00001000:  7f",
		"0xzz:  7f 45 ",
		"0x00001000 7f 45 ",
		"Memory at 0x",
		"Memory at 0x1000 (4 bytes):",
		"ERROR: Invalid memory address or access violation\n",
		"Size must be between 1 and 4096 bytes\n",
		"\n\n\n",
		":  7f 45 4c 46 \n",
		"0x11111111111111111111:  7f 45 \n",
	};
	static const int want[] = {
		1, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	};
	size_t i;
	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		int r = md (cases[i], 0x1000, out, sizeof (out));
		if (r != want[i]) {
			fprintf (stderr, "  case %d \"%s\": got %d, want %d\n", (int)i, cases[i], r, want[i]);
		}
		CHECK (r == want[i]);
	}
	/* a short line stops the dump: later lines no longer line up */
	CHECK (md ("0x00001000:  01 02 \n0x00001010:  03 04 \n", 0x1000, out, sizeof (out)) == 2);
	/* max = 0 and embedded NUL bytes in the reply */
	CHECK (md ("0x00001000:  01 02 \n", 0x1000, out, 0) == -1);
	{
		static const char nul[] = "0x00001000:  01 \0 02 \n0x00001001:  03 \n";
		char *p = exact (nul, sizeof (nul) - 1);
		CHECK (rn_parse_md (p, sizeof (nul) - 1, 0x1000, out, sizeof (out)) == 2);
		CHECK (out[0] == 0x01 && out[1] == 0x03);
		free (p);
	}
}

static void test_md_foreign_lines(void) {
	/* hook output printed in the middle of a dump, some of it shaped
	 * like a dump line */
	static const char dump[] =
		"[hook libc.so+0x1234 @0x7000001234] tid=1 x0=0x1\n"
		"Memory at 0x2000 (32 bytes):\n"
		"0x00002000:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  |................|\n"
		"0x00009999:  de ad be ef de ad be ef de ad be ef de ad be ef  |................|\n"
		"0x00002000:  ee ee ee ee ee ee ee ee ee ee ee ee ee ee ee ee  |................|\n"
		"0x00002010:  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f  |................|\n";
	uint8_t out[64];
	int i;
	CHECK (md (dump, 0x2000, out, sizeof (out)) == 32);
	for (i = 0; i < 32; i++) {
		CHECK (out[i] == i);
	}
}

/* ---- hex ---- */

static void test_hex(void) {
	uint8_t out[8];
	char *p = exact ("00ff1eA0", 8);
	CHECK (rn_hex_decode (p, 8, out, sizeof (out)) == 4);
	CHECK (out[0] == 0x00 && out[1] == 0xff && out[2] == 0x1e && out[3] == 0xa0);
	CHECK (rn_hex_decode (p, 7, out, sizeof (out)) == -1);     /* odd */
	CHECK (rn_hex_decode (p, 8, out, 3) == -1);                /* too long */
	CHECK (rn_hex_decode (p, 0, out, sizeof (out)) == 0);
	free (p);
	CHECK (rn_hex_decode ("0g", 2, out, sizeof (out)) == -1);
	CHECK (rn_hex_decode ("0\0" "00", 4, out, sizeof (out)) == -1);  /* embedded NUL */
	CHECK (rn_hex_decode (" 1", 2, out, sizeof (out)) == -1);

	RnBuf b;
	rn_buf_init (&b);
	static const uint8_t raw[] = { 0x00, 0x0a, 0x1e, 0xff, 0x7f };
	CHECK (rn_hex_encode (&b, raw, sizeof (raw)));
	CHECK (b.len == 10 && !strcmp (b.data, "000a1eff7f"));
	rn_buf_clear (&b);
	uint8_t big[1000], back[1000];
	int i;
	for (i = 0; i < 1000; i++) {
		big[i] = (uint8_t)(i * 7);
	}
	CHECK (rn_hex_encode (&b, big, sizeof (big)) && b.len == 2000);
	CHECK (rn_hex_decode (b.data, b.len, back, sizeof (back)) == 1000 && !memcmp (big, back, 1000));
	rn_buf_fini (&b);
}

/* ---- buffer ---- */

static void test_buf(void) {
	RnBuf b;
	rn_buf_init (&b);
	/* embedded NULs are data, not terminators */
	CHECK (rn_buf_append (&b, "ab\0cd", 5));
	CHECK (rn_buf_append (&b, "\0\0", 2));
	CHECK (rn_buf_appendf (&b, "%d-%s", 42, "x"));
	CHECK (b.len == 11 && !memcmp (b.data, "ab\0cd\0\0" "42-x", 11) && b.data[11] == '\0');
	rn_buf_consume (&b, 3);
	CHECK (b.len == 8 && !memcmp (b.data, "cd\0\0" "42-x", 8));
	rn_buf_consume (&b, 100);
	CHECK (b.len == 0);
	size_t n = 99;
	char *s = rn_buf_steal (&b, &n);
	CHECK (s && n == 0 && s[0] == '\0');
	free (s);
	int i;
	for (i = 0; i < 100000; i++) {
		rn_buf_append (&b, "\0x", 2);
	}
	CHECK (b.len == 200000 && b.data[199999] == 'x' && b.data[199998] == '\0');
	rn_buf_fini (&b);
}

/* ---- framing reader ---- */

static void test_frame_request(void) {
	RnBuf b;
	rn_buf_init (&b);
	CHECK (rn_frame_request (&b, 7, "exec print(1)\n", 14));
	CHECK (b.len == 24 && !memcmp (b.data, "@req 7 14\nexec print(1)\n", 24));
	rn_buf_clear (&b);
	CHECK (rn_frame_request (&b, 12345, "a\0b\n", 4));
	CHECK (b.len == 17 && !memcmp (b.data, "@req 12345 4\na\0b\n", 17));
	rn_buf_fini (&b);
}

static void test_reader_basic(void) {
	RnReader r;
	RnBuf out;
	rn_reader_init (&r);
	rn_buf_init (&out);

	rn_reader_sent (&r, 1);
	rn_reader_feed (&r, "pong\n\x1e@done 1\n", 14);
	CHECK (rn_reader_poll (&r, 1, &out));
	CHECK (out.len == 5 && !memcmp (out.data, "pong\n", 5));
	CHECK (r.buf.len == 0 && r.n_out == 0);

	/* nothing buffered: not done, nothing handed out */
	rn_buf_clear (&out);
	rn_reader_sent (&r, 2);
	CHECK (!rn_reader_poll (&r, 2, &out) && out.len == 0);
	/* output without a marker is handed out as it comes */
	rn_reader_feed (&r, "line 1\nli", 9);
	CHECK (!rn_reader_poll (&r, 2, &out));
	CHECK (out.len == 9);
	rn_reader_feed (&r, "ne 2\n\x1e@do", 9);
	CHECK (!rn_reader_poll (&r, 2, &out));
	CHECK (out.len == 14);                       /* the partial marker is held back */
	rn_reader_feed (&r, "ne 2\n", 5);
	CHECK (rn_reader_poll (&r, 2, &out));
	CHECK (out.len == 14 && !memcmp (out.data, "line 1\nline 2\n", 14));

	/* an empty reply */
	rn_buf_clear (&out);
	rn_reader_sent (&r, 3);
	rn_reader_feed (&r, "\x1e@done 3\n", 9);
	CHECK (rn_reader_poll (&r, 3, &out) && out.len == 0);

	rn_buf_fini (&out);
	rn_reader_fini (&r);
}

static void test_reader_stale(void) {
	RnReader r;
	RnBuf out;
	rn_reader_init (&r);
	rn_buf_init (&out);

	/* Request 1 was given up on. Its reply arrives in front of the reply
	 * to request 2 and must be dropped whole - including when it is
	 * longer than the marker (the offset bug found in ResponseReader:
	 * erasing nl+1 bytes after the segment had already been removed ate
	 * the start of the next reply). */
	rn_reader_sent (&r, 1);
	rn_reader_sent (&r, 2);
	CHECK (rn_reader_busy_with_older (&r, 2));
	static const char s1[] = "a late and fairly long reply to request one\n\x1e@done 1\n" "BB\n\x1e@done 2\n";
	rn_reader_feed (&r, s1, sizeof (s1) - 1);
	CHECK (rn_reader_poll (&r, 2, &out));
	CHECK (out.len == 3 && !memcmp (out.data, "BB\n", 3));
	CHECK (r.buf.len == 0 && r.n_out == 0);
	CHECK (!rn_reader_busy_with_older (&r, 2));

	/* three abandoned requests, the fourth is ours */
	rn_buf_clear (&out);
	rn_reader_sent (&r, 3);
	rn_reader_sent (&r, 4);
	rn_reader_sent (&r, 5);
	rn_reader_sent (&r, 6);
	static const char s2[] = "three\n\x1e@done 3\n" "\x1e@done 4\n" "five five five\n\x1e@done 5\n" "six\n\x1e@done 6\n" "next";
	rn_reader_feed (&r, s2, sizeof (s2) - 1);
	CHECK (rn_reader_poll (&r, 6, &out));
	CHECK (out.len == 4 && !memcmp (out.data, "six\n", 4));
	CHECK (r.buf.len == 4 && !memcmp (r.buf.data, "next", 4));   /* the following reply is intact */

	/* the reply of an abandoned request that never gets its marker is
	 * still not ours */
	rn_reader_reset (&r);
	rn_buf_clear (&out);
	rn_reader_sent (&r, 7);
	rn_reader_sent (&r, 8);
	rn_reader_feed (&r, "belongs to seven", 16);
	CHECK (!rn_reader_poll (&r, 8, &out) && out.len == 0);
	rn_reader_feed (&r, "\n\x1e@done 7\neight\n\x1e@done 8\n", 26);
	CHECK (rn_reader_poll (&r, 8, &out));
	CHECK (out.len == 6 && !memcmp (out.data, "eight\n", 6));

	/* a marker with a higher id than everything outstanding clears them */
	rn_reader_reset (&r);
	rn_buf_clear (&out);
	rn_reader_sent (&r, 9);
	rn_reader_sent (&r, 10);
	rn_reader_feed (&r, "x\x1e@done 10\n", 11);
	CHECK (rn_reader_poll (&r, 10, &out) && r.n_out == 0);

	rn_buf_fini (&out);
	rn_reader_fini (&r);
}

static void test_reader_binary(void) {
	RnReader r;
	RnBuf out;
	rn_reader_init (&r);
	rn_buf_init (&out);
	/* NUL bytes, lone 0x1e bytes and near-markers are payload */
	static const char body[] = "a\0b\x1e\x1e@don\x1e@done\x1e@dony 3\n\0\0\x1e";
	static const char mark[] = "\x1e@done 11\n";
	rn_reader_sent (&r, 11);
	rn_reader_feed (&r, body, sizeof (body) - 1);
	rn_reader_feed (&r, mark, sizeof (mark) - 1);
	CHECK (rn_reader_poll (&r, 11, &out));
	CHECK (out.len == sizeof (body) - 1 && !memcmp (out.data, body, sizeof (body) - 1));
	rn_buf_fini (&out);
	rn_reader_fini (&r);
}

static void test_reader_drain(void) {
	RnReader r;
	RnBuf out;
	rn_reader_init (&r);
	rn_buf_init (&out);
	/* output with no request waiting, around the marker of an old one */
	rn_reader_sent (&r, 4);
	static const char s[] = "hook fired\n\x1e@done 4\nagain\n\x1e@do";
	rn_reader_feed (&r, s, sizeof (s) - 1);
	rn_reader_drain (&r, &out);
	CHECK (out.len == 17 && !memcmp (out.data, "hook fired\nagain\n", 17));
	CHECK (r.n_out == 0);
	CHECK (r.buf.len == 4);                      /* possible start of a marker stays */
	rn_reader_feed (&r, "ne 9\ntail", 9);
	rn_buf_clear (&out);
	rn_reader_drain (&r, &out);
	CHECK (out.len == 4 && !memcmp (out.data, "tail", 4) && r.buf.len == 0);
	rn_buf_fini (&out);
	rn_reader_fini (&r);
}

/* A reply stream and what request `want` must get out of it, fed in every
 * possible chunking: the result may not depend on where the reads split. */
static void run_chunked(const char *stream, size_t stream_len, const unsigned long *sent, size_t n_sent,
		unsigned long want, const char *expect, size_t expect_len, size_t expect_left) {
	size_t chunk, i;
	for (chunk = 1; chunk <= stream_len; chunk++) {
		RnReader r;
		RnBuf out;
		bool done = false;
		rn_reader_init (&r);
		rn_buf_init (&out);
		for (i = 0; i < n_sent; i++) {
			rn_reader_sent (&r, sent[i]);
		}
		size_t fed = 0;
		for (i = 0; i < stream_len && !done; i += chunk) {
			size_t n = stream_len - i < chunk? stream_len - i: chunk;
			char *piece = exact (stream + i, n);
			rn_reader_feed (&r, piece, n);
			free (piece);
			fed = i + n;
			done = rn_reader_poll (&r, want, &out);
		}
		if (!done || out.len != expect_len || memcmp (out.data? out.data: "", expect, expect_len)
				|| r.buf.len + (stream_len - fed) != expect_left) {
			fprintf (stderr, "  chunk size %d: done=%d out.len=%d left=%d\n", (int)chunk, (int)done,
				(int)out.len, (int)(r.buf.len + (stream_len - fed)));
		}
		CHECK (done);
		CHECK (out.len == expect_len && !memcmp (out.data? out.data: "", expect, expect_len));
		CHECK (r.buf.len + (stream_len - fed) == expect_left);
		rn_buf_fini (&out);
		rn_reader_fini (&r);
	}
}

static void test_reader_chunks(void) {
	{
		static const char s[] = "pong\n\x1e@done 1\n";
		static const unsigned long sent[] = { 1 };
		run_chunked (s, sizeof (s) - 1, sent, 1, 1, "pong\n", 5, 0);
	}
	{
		/* stale reply first, a payload full of marker look-alikes, and
		 * the beginning of the next reply behind it */
		static const char s[] =
			"stale stale stale\n\x1e@done 20\n"
			"\x1e@don\0 A\x1e\x1e@done\n\x1e@dona 1\nB\n"
			"\x1e@done 21\n"
			"NEXT\x1e@done 22\n";
		static const char want[] = "\x1e@don\0 A\x1e\x1e@done\n\x1e@dona 1\nB\n";
		static const unsigned long sent[] = { 20, 21, 22 };
		run_chunked (s, sizeof (s) - 1, sent, 3, 21, want, sizeof (want) - 1, 14);
	}
	{
		/* ids with several digits; only the exact id completes */
		static const char s[] = "x\x1e@done 1\ny\x1e@done 12\nz\x1e@done 123\n";
		static const unsigned long sent[] = { 1, 12, 123 };
		run_chunked (s, sizeof (s) - 1, sent, 3, 123, "z", 1, 0);
		run_chunked (s, sizeof (s) - 1, sent, 3, 12, "y", 1, 12);
	}
}

/* ---- /proc/self/maps ---- */

static void test_maps_line(void) {
	RnMapLine m;
	static const char l1[] = "7000004000-7000010000 r-xp 00004000 fd:00 1234                           /apex/com.android.runtime/lib64/bionic/libc.so\n";
	CHECK (rn_parse_maps_line (l1, sizeof (l1) - 1, &m));
	CHECK (m.start == 0x7000004000ULL && m.end == 0x7000010000ULL && m.offset == 0x4000);
	CHECK (!strcmp (m.perms, "r-xp") && !strcmp (m.path, "/apex/com.android.runtime/lib64/bionic/libc.so"));

	static const char l2[] = "7ff0000000-7ff0021000 rw-p 00000000 00:00 0";
	CHECK (rn_parse_maps_line (l2, sizeof (l2) - 1, &m) && m.path[0] == '\0' && !strcmp (m.perms, "rw-p"));

	static const char l3[] = "7b5c1d2000-7b5c1d3000 ---p 00000000 00:00 0                              [anon:stack_and_tls:main]";
	CHECK (rn_parse_maps_line (l3, sizeof (l3) - 1, &m) && !strcmp (m.path, "[anon:stack_and_tls:main]"));

	static const char l4[] = "7000000000-7000001000 r--p 00000000 fd:00 99 /data/local/tmp/my lib.so (deleted)";
	CHECK (rn_parse_maps_line (l4, sizeof (l4) - 1, &m) && !strcmp (m.path, "/data/local/tmp/my lib.so (deleted)"));

	static const char *const bad[] = {
		"", "garbage", "7000-", "7000-6000 r--p 0 0 0", "7000-8000", "7000-8000 r-- 0 0 0",
		"zz-8000 r--p 0 0 0", "7000-8000 r--p", "-", "7000 8000 r--p 0 0 0",
	};
	size_t i;
	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
		char *p = exact (bad[i], strlen (bad[i]));
		CHECK (!rn_parse_maps_line (p, strlen (bad[i]), &m));
		free (p);
	}
	/* a path longer than the field is cut, not overrun */
	char longl[600];
	memset (longl, 'a', sizeof (longl));
	memcpy (longl, "7000-8000 r--p 00000000 fd:00 1 /", 33);
	CHECK (rn_parse_maps_line (longl, sizeof (longl), &m) && strlen (m.path) == sizeof (m.path) - 1);
}

/* ---- URI ---- */

static void test_uri(void) {
	RnUri u;
	const char *err = NULL;
	/* the URI the old tests/cmd_parser.c took apart */
	CHECK (rn_parse_uri ("renef://spawn/io.byterialab.moduletest", "127.0.0.1", "1907", &u, &err));
	CHECK (u.spawn && !strcmp (u.target, "io.byterialab.moduletest"));
	CHECK (!strcmp (u.host, "127.0.0.1") && !strcmp (u.port, "1907") && err == NULL);

	CHECK (rn_parse_uri ("renef://attach/12345", "127.0.0.1", "1907", &u, &err));
	CHECK (!u.spawn && !strcmp (u.target, "12345"));

	CHECK (rn_parse_uri ("renef://10.0.0.5:19070/spawn/com.example.app", "127.0.0.1", "1907", &u, &err));
	CHECK (u.spawn && !strcmp (u.host, "10.0.0.5") && !strcmp (u.port, "19070") && !strcmp (u.target, "com.example.app"));

	CHECK (rn_parse_uri ("renef://devbox/attach/7/", "127.0.0.1", "2000", &u, &err));
	CHECK (!strcmp (u.host, "devbox") && !strcmp (u.port, "2000") && !strcmp (u.target, "7"));

	CHECK (rn_parse_uri ("renef://[::1]:19070/attach/7", "127.0.0.1", "1907", &u, &err));
	CHECK (!strcmp (u.host, "::1") && !strcmp (u.port, "19070"));

	/* host and port defaults come from the caller (environment) */
	CHECK (rn_parse_uri ("renef://spawn/a.b", "192.168.1.9", "4000", &u, &err));
	CHECK (!strcmp (u.host, "192.168.1.9") && !strcmp (u.port, "4000"));

	static const char *const bad[] = {
		"renef://", "renef://spawn", "renef://spawn/", "renef://attach/abc", "renef://attach/12 3",
		"renef://spawn/com.x y", "renef://spawn/com.x\nexec os.exit()", "renef://spawn/com.x;la",
		"renef://host:0/spawn/a.b", "renef://host:99999/spawn/a.b", "renef://host:12a/spawn/a.b",
		"renef://host/run/a.b", "renef://host:1907", "renef://[::1/spawn/a.b", "renef://kill/1",
	};
	size_t i;
	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
		err = NULL;
		bool ok = rn_parse_uri (bad[i], "127.0.0.1", "1907", &u, &err);
		if (ok) {
			fprintf (stderr, "  accepted \"%s\"\n", bad[i]);
		}
		CHECK (!ok && err != NULL);
	}
	CHECK (!rn_parse_uri ("renef://spawn/a.b", "127.0.0.1", "notaport", &u, &err));
}

/* ---- Lua helpers ---- */

static void test_lua_quote(void) {
	RnBuf b;
	rn_buf_init (&b);
	CHECK (rn_lua_quote (&b, "libc.so", 7) && !strcmp (b.data, "\"libc.so\""));
	rn_buf_clear (&b);
	CHECK (rn_lua_quote (&b, "a\"b\\c\nd\0e", 9));
	CHECK (!strcmp (b.data, "\"a\\\"b\\\\c\\010d\\000e\""));
	/* the server splits the command name at "//" and a newline ends a
	 * legacy command: neither may survive quoting */
	rn_buf_clear (&b);
	CHECK (rn_lua_quote (&b, "/data//app///x\r\n", 16));
	CHECK (!strstr (b.data, "//") && !strchr (b.data, '\n') && !strchr (b.data, '\r'));
	CHECK (!strcmp (b.data, "\"/data/\\047app/\\047\\047x\\013\\010\""));
	rn_buf_fini (&b);
}

static void test_lua_wrap(void) {
	RnBuf b;
	rn_buf_init (&b);
	static const char script[] = "-- comment\nprint(7//2)\nprint(\"http://x\")\n";
	CHECK (rn_lua_wrap_script (&b, script, sizeof (script) - 1, "@demo.lua"));
	CHECK (!strstr (b.data, "//") && !strchr (b.data, '\n'));
	CHECK (strstr (b.data, "2d2d20636f6d6d656e740a") != NULL);   /* "-- comment\n" in hex */
	CHECK (strstr (b.data, "\"@demo.lua\"") != NULL);
	rn_buf_fini (&b);
}

static void test_search_pattern(void) {
	char *p;
	p = rn_search_pattern ("504b0304", 8, true);
	CHECK (p && !strcmp (p, "50 4B 03 04 "));
	free (p);
	p = rn_search_pattern ("50 4b ?? 04", 11, true);
	CHECK (p && !strcmp (p, "50 4B ?? 04 "));
	free (p);
	p = rn_search_pattern ("50..03", 6, true);
	CHECK (p && !strcmp (p, "50 ?? 03 "));
	free (p);
	/* one byte still gets the blank that makes Memory.search() treat it
	 * as a byte pattern */
	p = rn_search_pattern ("7f", 2, true);
	CHECK (p && !strcmp (p, "7F "));
	free (p);
	/* text is searched as bytes: a blank or "??" in it cannot be misread */
	p = rn_search_pattern ("a ??", 4, false);
	CHECK (p && !strcmp (p, "61 20 3F 3F "));
	free (p);
	CHECK (!rn_search_pattern ("", 0, true));
	CHECK (!rn_search_pattern ("5", 1, true));
	CHECK (!rn_search_pattern ("504", 3, true));
	CHECK (!rn_search_pattern ("zz", 2, true));
	CHECK (!rn_search_pattern ("5?", 2, true));
	CHECK (!rn_search_pattern ("", 0, false));
	char big[600];
	memset (big, 'a', sizeof (big));
	CHECK (!rn_search_pattern (big, 257, false));
	CHECK (!rn_search_pattern (big, 514, true));
	p = rn_search_pattern (big, 512, true);
	CHECK (p && strlen (p) == 256 * 3);
	free (p);
}

static void test_base64(void) {
	RnBuf b;
	rn_buf_init (&b);
	CHECK (rn_base64_encode (&b, "", 0) && b.len == 0);
	CHECK (rn_base64_encode (&b, "f", 1) && !strcmp (b.data, "Zg=="));
	rn_buf_clear (&b);
	CHECK (rn_base64_encode (&b, "fo", 2) && !strcmp (b.data, "Zm8="));
	rn_buf_clear (&b);
	CHECK (rn_base64_encode (&b, "foobar", 6) && !strcmp (b.data, "Zm9vYmFy"));
	rn_buf_clear (&b);
	CHECK (rn_base64_encode (&b, "\xff\x00\xfe", 3) && !strcmp (b.data, "/wD+"));
	rn_buf_fini (&b);
}

int main(void) {
	test_md_basic ();
	test_md_header_and_partial_line ();
	test_md_ascii_column ();
	test_md_malformed ();
	test_md_foreign_lines ();
	test_hex ();
	test_buf ();
	test_frame_request ();
	test_reader_basic ();
	test_reader_stale ();
	test_reader_binary ();
	test_reader_drain ();
	test_reader_chunks ();
	test_maps_line ();
	test_uri ();
	test_lua_quote ();
	test_lua_wrap ();
	test_search_pattern ();
	test_base64 ();
	printf ("test_proto: %d checks, %d failed\n", g_checks, g_failed);
	return g_failed? 1: 0;
}
