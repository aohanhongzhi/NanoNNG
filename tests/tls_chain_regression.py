#!/usr/bin/env python3
"""Check OpenSSL certificate-chain loading using a built static libnng.a.

Usage: python3 tests/tls_chain_regression.py /path/to/libnng.a
Requires cc and openssl. Generates disposable certificates; binds only localhost.
"""

import os
from pathlib import Path
import select
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile


SERVER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nng/nng.h>
#include <nng/supplemental/tls/tls.h>

static char *load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) exit(2);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *s = calloc((size_t)n + 1, 1);
    if (!s || fread(s, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f);
    return s;
}
#define CHECK(call) do { int e = (call); if (e) { \
    fprintf(stderr, "%s: %s\n", #call, nng_strerror(e)); exit(2); } } while (0)

int main(int argc, char **argv) {
    nng_tls_config *cfg;
    nng_stream_listener *listener;
    nng_aio *aio;
    char *cert = load(argv[1]), *key = load(argv[2]);
    CHECK(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER));
    CHECK(nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE));
    int rv = nng_tls_config_own_cert(cfg, cert, key, NULL);
    free(cert); free(key);
    if (strcmp(argv[3], "invalid") == 0) {
        nng_tls_config_free(cfg);
        nng_fini();
        return rv == NNG_EINVAL ? 0 : 1;
    }
    CHECK(rv);
    // Exercise replacement too: old intermediates must not accumulate.
    if (argc > 4) {
        cert = load(argv[4]); key = load(argv[2]);
        CHECK(nng_tls_config_own_cert(cfg, cert, key, NULL));
        free(cert); free(key);
    }
    CHECK(nng_stream_listener_alloc(&listener, "tls+tcp://127.0.0.1:0"));
    CHECK(nng_stream_listener_set_ptr(listener, NNG_OPT_TLS_CONFIG, cfg));
    CHECK(nng_stream_listener_listen(listener));
    int port;
    CHECK(nng_stream_listener_get_int(listener, NNG_OPT_TCP_BOUND_PORT, &port));
    printf("%d\n", port); fflush(stdout);
    CHECK(nng_aio_alloc(&aio, NULL, NULL));
    nng_aio_set_timeout(aio, 10000);
    nng_stream_listener_accept(listener, aio);
    nng_aio_wait(aio);
    rv = nng_aio_result(aio);
    if (rv == 0) {
        nng_stream *stream = nng_aio_get_output(aio, 0);
        char byte; nng_iov iov = { &byte, 1 };
        CHECK(nng_aio_set_iov(aio, 1, &iov));
        nng_stream_recv(stream, aio);
        nng_aio_wait(aio);
        if (nng_aio_result(aio) == 0) {
            CHECK(nng_aio_set_iov(aio, 1, &iov));
            nng_stream_send(stream, aio);
            nng_aio_wait(aio);
        }
        nng_stream_free(stream);
    }
    nng_aio_free(aio);
    nng_stream_listener_free(listener);
    nng_tls_config_free(cfg);
    nng_fini();
    return 0;
}
'''


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=30)


def main():
    library = Path(sys.argv[1]).resolve()
    source = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="nng-tls-chain-") as directory:
        tmp = Path(directory)
        (tmp / "server.c").write_text(SERVER)
        server = str(tmp / "server")
        run(*shlex.split(os.environ.get("CC", "cc")),
            "-I" + str(source / "include"), str(tmp / "server.c"),
            str(library), "-lssl", "-lcrypto", "-lpthread", "-ldl", "-lm",
            "-o", server)
        for name in ("root", "intermediate", "leaf"):
            run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=" + ("localhost" if name == "leaf" else name),
                "-keyout", str(tmp / (name + ".key")),
                "-out", str(tmp / (name + ".csr")))
        (tmp / "root.cnf").write_text("basicConstraints=critical,CA:TRUE\n"
                                      "keyUsage=critical,keyCertSign,cRLSign\n")
        run("openssl", "x509", "-req", "-in", str(tmp / "root.csr"),
            "-signkey", str(tmp / "root.key"), "-days", "1",
            "-extfile", str(tmp / "root.cnf"), "-out", str(tmp / "root.pem"))
        for name, issuer in (("intermediate", "root"), ("leaf", "intermediate")):
            extensions = ("basicConstraints=critical,CA:TRUE\n"
                          "keyUsage=critical,keyCertSign,cRLSign\n"
                          if name == "intermediate" else
                          "basicConstraints=critical,CA:FALSE\n"
                          "subjectAltName=DNS:localhost\n"
                          "extendedKeyUsage=serverAuth\n")
            (tmp / "ext.cnf").write_text(extensions)
            run("openssl", "x509", "-req", "-in", str(tmp / (name + ".csr")),
                "-CA", str(tmp / (issuer + ".pem")), "-CAkey",
                str(tmp / (issuer + ".key")), "-CAcreateserial", "-days", "1",
                "-extfile", str(tmp / "ext.cnf"), "-out", str(tmp / (name + ".pem")))
        leaf = (tmp / "leaf.pem").read_text()
        chain = leaf + (tmp / "intermediate.pem").read_text()
        cases = [
            ("fullchain", chain, True, None),
            ("whitespace", chain + "\n \t\r\n", True, None),
            ("leaf-only", leaf, False, None),
            ("replace-chain", chain, False, "leaf.pem"),
            ("replace-leaf", leaf, True, "fullchain.pem"),
        ]
        (tmp / "fullchain.pem").write_text(chain)
        context = ssl.create_default_context(cafile=str(tmp / "root.pem"))
        for name, content, expected, replacement in cases:
            pem = tmp / "case.pem"
            pem.write_text(content)
            args = [server, str(pem), str(tmp / "leaf.key"), "serve"]
            if replacement:
                args.append(str(tmp / replacement))
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                if not select.select([proc.stdout], [], [], 10)[0]:
                    raise AssertionError("Listener did not start")
                port = int(proc.stdout.readline())
                verified = True
                try:
                    with context.wrap_socket(socket.create_connection(("127.0.0.1", port), 10),
                                             server_hostname="localhost") as conn:
                        conn.sendall(b"x")
                        assert conn.recv(1) == b"x"
                except ssl.SSLCertVerificationError:
                    verified = False
                except ssl.SSLError:
                    _, errors = proc.communicate(timeout=15)
                    print(errors.decode(), file=sys.stderr)
                    raise
                assert verified == expected, name
                _, errors = proc.communicate(timeout=15)
                assert proc.returncode == 0, errors.decode()
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            print("PASS", name)
        for suffix in ("garbage", "-----BEGIN CERTIFICATE-----\ninvalid\n",
                       "-----BEGIN CERTIFICATE-----\n"):
            (tmp / "case.pem").write_text(chain + suffix)
            run(server, str(tmp / "case.pem"), str(tmp / "leaf.key"), "invalid")
        print("PASS malformed trailing chain (3 cases)")


if __name__ == "__main__":
    main()
