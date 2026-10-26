The localhost certificate and private key are public test fixtures only. They are
used by the loopback TLS measurement test, never loaded by the application or
included in the portable build. The test explicitly trusts this certificate and
also verifies that the application's default trust rejects it.
