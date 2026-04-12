# shellcheck shell=bash

Describe "cluster-entrypoint.sh helpers"
  Include ./cluster-entrypoint.sh

  setup() {
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cluster-entrypoint-spec.XXXXXX")
    DATA_DIR="$temp_dir/runtime/data"
    mkdir -p "$DATA_DIR"
    NODE_CONF_FILE="$DATA_DIR/node.conf"
    : > "$NODE_CONF_FILE"
    NODE_HOST="cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud"
    NODE_PORT=6379
    BUS_PORT=16379
    TLS=false
    POD_IP="10.0.0.10"
    INSTANCE_ID=""
    DNS_SUFFIX=""
    ADMIN_PASSWORD="testpass"
    sleep() {
      SECONDS=$((SECONDS + 301))
    }

    sed() {
      if [[ "$1" == "-i" && "$2" == "-E" ]]; then
        perl -0pi -e "$3" "$4"
      else
        /usr/bin/sed "$@"
      fi
    }

    unset -f getent
  }
  BeforeEach 'setup'

  teardown() {
    rm -rf "$temp_dir"
    unset DATA_DIR NODE_CONF_FILE NODE_HOST NODE_PORT BUS_PORT TLS POD_IP INSTANCE_ID DNS_SUFFIX ADMIN_PASSWORD
    unset -f getent sed sleep
  }
  AfterEach 'teardown'

  Describe "read_secret_or_env()"
    It "reads value from a secret file when present"
      echo -n "secret_val" > "$temp_dir/secret_file"
      When call read_secret_or_env "$temp_dir/secret_file" "UNUSED_ENV"
      The status should be success
      The output should eq "secret_val"
    End

    It "falls back to environment variable when secret file missing"
      MY_TEST_VAR="env_val"
      When call read_secret_or_env "/nonexistent/path" "MY_TEST_VAR"
      The status should be success
      The output should eq "env_val"
      unset MY_TEST_VAR
    End

    It "returns empty when neither secret file nor env var exists"
      When call read_secret_or_env "/nonexistent/path" "TOTALLY_MISSING_VAR"
      The status should be success
      The output should eq ""
    End

    It "ignores an empty secret file and falls back to env var"
      : > "$temp_dir/empty_secret"
      FALLBACK_VAR="fallback"
      When call read_secret_or_env "$temp_dir/empty_secret" "FALLBACK_VAR"
      The status should be success
      The output should eq "fallback"
      unset FALLBACK_VAR
    End
  End

  Describe "resolve_host_ip()"
    It "returns a literal IP without DNS lookup"
      When call resolve_host_ip "10.0.0.42"
      The status should be success
      The output should eq "10.0.0.42"
    End

    It "resolves a hostname via getent"
      getent() {
        if [[ "$2" == "myhost.example.com" ]]; then
          echo "10.0.0.99 myhost.example.com"
        else
          return 1
        fi
      }

      When call resolve_host_ip "myhost.example.com"
      The status should be success
      The output should eq "10.0.0.99"
    End

    It "times out when a hostname never resolves"
      getent() {
        return 1
      }

      sleep() {
        SECONDS=$((SECONDS + 301))
      }

      When run resolve_host_ip "cluster-sz-1.internal" "peer node" 0
      The status should be failure
      The stderr should include "Timed out trying to resolve ip for peer node: cluster-sz-1.internal"
    End
  End

  Describe "fix_namespace_in_config_files()"
    It "rewrites namespace in both node.conf and nodes.conf"
      INSTANCE_ID="instance-new"

      cat <<'EOF' > "$NODE_CONF_FILE"
cluster-announce-hostname cluster-sz-0.instance-old.hc-old.us-central1.gcp.deadbeef.cloud
EOF
      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 192.168.1.10:6379@16379,cluster-sz-0.instance-old.hc-old.us-central1.gcp.deadbeef.cloud myself,master - 0 0 1 connected
EOF

      When call fix_namespace_in_config_files
      The status should be success
      The output should include "Current namespace: instance-new"
      The contents of file "$NODE_CONF_FILE" should include "instance-new"
      The contents of file "$NODE_CONF_FILE" should not include "instance-old"
      The contents of file "$DATA_DIR/nodes.conf" should include "instance-new"
    End

    It "rewrites DNS suffix in both node.conf and nodes.conf"
      DNS_SUFFIX="hc-new.us-central1.gcp.beef.cloud"

      cat <<'EOF' > "$NODE_CONF_FILE"
cluster-announce-hostname cluster-sz-0.instance-abc.hc-old.us-central1.gcp.deadbeef.cloud
EOF
      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 192.168.1.10:6379@16379,cluster-sz-0.instance-abc.hc-old.us-central1.gcp.deadbeef.cloud myself,master - 0 0 1 connected
EOF

      When call fix_namespace_in_config_files
      The status should be success
      The output should include "Current DNS suffix:"
      The contents of file "$NODE_CONF_FILE" should include "hc-new.us-central1.gcp.beef.cloud"
      The contents of file "$DATA_DIR/nodes.conf" should include "hc-new.us-central1.gcp.beef.cloud"
      The contents of file "$DATA_DIR/nodes.conf" should not include "deadbeef"
    End

    It "skips when INSTANCE_ID and DNS_SUFFIX are not set"
      When call fix_namespace_in_config_files
      The status should be success
      The output should include "INSTANCE_ID not set, skipping namespace fix"
      The output should include "DNS_SUFFIX not set, skipping DNS suffix fix"
    End

    It "is idempotent when DNS suffix is already correct"
      DNS_SUFFIX="hc-new.us-central1.gcp.beef.cloud"

      cat <<'EOF' > "$NODE_CONF_FILE"
cluster-announce-hostname cluster-sz-0.instance-abc.hc-new.us-central1.gcp.beef.cloud
EOF

      When call fix_namespace_in_config_files
      The status should be success
      The output should include "Current DNS suffix:"
      The contents of file "$NODE_CONF_FILE" should include "cluster-sz-0.instance-abc.hc-new.us-central1.gcp.beef.cloud"
    End
  End

  Describe "prepare_node_files_for_startup()"
    It "rewrites namespace and DNS suffix before resolving node IPs"
      INSTANCE_ID="instance-new"
      DNS_SUFFIX="hc-new.us-central1.gcp.beef.cloud"

      cat <<'EOF' > "$NODE_CONF_FILE"
cluster-announce-hostname cluster-sz-0.instance-old.hc-old.us-central1.gcp.deadbeef.cloud
EOF

      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 192.168.1.10:6379@16379,cluster-sz-0.instance-old.hc-old.us-central1.gcp.deadbeef.cloud myself,master - 0 0 1 connected
2a2c0f54d8c4aa11 192.168.1.11:6379@16379,cluster-sz-1.instance-old.hc-old.us-central1.gcp.deadbeef.cloud master - 0 0 2 connected
EOF

      getent() {
        case "$2" in
          cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.10 $2"
            ;;
          cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.11 $2"
            ;;
          *)
            return 1
            ;;
        esac
      }

      When call prepare_node_files_for_startup
      The status should be success
      The output should include "Updating IP for node cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud"
      The contents of file "$NODE_CONF_FILE" should include "cluster-announce-hostname cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud"
      The contents of file "$DATA_DIR/nodes.conf" should include "10.0.0.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself"
      The contents of file "$DATA_DIR/nodes.conf" should include "10.0.0.11:6379@16379,cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud"
    End

    It "returns success when nodes.conf does not exist"
      rm -f "$DATA_DIR/nodes.conf"

      When call prepare_node_files_for_startup
      The status should be success
      The output should include "First time running the node.."
    End
  End

  Describe "update_ips_in_nodes_conf()"
    It "resolves the current node hostname when POD_IP is not set"
      unset POD_IP

      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 192.168.1.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself,master - 0 0 1 connected
2a2c0f54d8c4aa11 192.168.1.11:6379@16379,cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud master - 0 0 2 connected
EOF

      getent() {
        case "$2" in
          cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.20 $2"
            ;;
          cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.21 $2"
            ;;
          *)
            return 1
            ;;
        esac
      }

      When call update_ips_in_nodes_conf
      The status should be success
      The output should include "Updating local node address: 192.168.1.10:6379@16379 -> 10.0.0.20:6379@16379"
      The contents of file "$DATA_DIR/nodes.conf" should include "10.0.0.20:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself"
      The contents of file "$DATA_DIR/nodes.conf" should include "10.0.0.21:6379@16379,cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud"
    End

    It "uses port 0 for the current node when TLS is enabled"
      TLS=true

      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 192.168.1.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself,master - 0 0 1 connected
2a2c0f54d8c4aa11 192.168.1.11:6379@16379,cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud master - 0 0 2 connected
EOF

      getent() {
        case "$2" in
          cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.11 $2"
            ;;
          *)
            return 1
            ;;
        esac
      }

      When call update_ips_in_nodes_conf
      The status should be success
      The output should include "Updating local node address: 192.168.1.10:6379@16379 -> 10.0.0.10:0@16379"
      The contents of file "$DATA_DIR/nodes.conf" should include "10.0.0.10:0@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself"
    End

    It "fails when a peer hostname never resolves"
      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 192.168.1.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself,master - 0 0 1 connected
2a2c0f54d8c4aa11 192.168.1.11:6379@16379,cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud master - 0 0 2 connected
EOF

      getent() {
        return 1
      }

      sleep() {
        SECONDS=$((SECONDS + 301))
      }

      When run update_ips_in_nodes_conf
      The status should be failure
      The stdout should include "Updating local node address: 192.168.1.10:6379@16379 -> 10.0.0.10:6379@16379"
      The stderr should include "Timed out trying to resolve ip for cluster node hostname: cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud"
    End

    It "skips lines with no resolvable hostname"
      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 10.0.0.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself,master - 0 0 1 connected
2a2c0f54d8c4aa11 192.168.1.11:6379@16379 master - 0 0 2 connected
EOF

      getent() {
        case "$2" in
          cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.10 $2"
            ;;
          *)
            return 1
            ;;
        esac
      }

      When call update_ips_in_nodes_conf
      The status should be success
      The output should include "No resolvable hostname found for node with addr: 192.168.1.11:6379@16379"
      The contents of file "$DATA_DIR/nodes.conf" should include "192.168.1.11:6379@16379"
    End

    It "preserves comment and header lines"
      cat <<'EOF' > "$DATA_DIR/nodes.conf"
# Some comment
07c37dfeb2352e66 10.0.0.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself,master - 0 0 1 connected
vars currentEpoch 1 lastVoteEpoch 0
EOF

      getent() {
        return 1
      }

      When call update_ips_in_nodes_conf
      The status should be success
      The output should include "Updating local node address"
      The contents of file "$DATA_DIR/nodes.conf" should include "# Some comment"
      The contents of file "$DATA_DIR/nodes.conf" should include "vars currentEpoch"
    End

    It "does not change IPs that are already correct"
      cat <<'EOF' > "$DATA_DIR/nodes.conf"
07c37dfeb2352e66 10.0.0.10:6379@16379,cluster-sz-0.instance-new.hc-new.us-central1.gcp.beef.cloud myself,master - 0 0 1 connected
2a2c0f54d8c4aa11 10.0.0.11:6379@16379,cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud master - 0 0 2 connected
EOF

      getent() {
        case "$2" in
          cluster-sz-1.instance-new.hc-new.us-central1.gcp.beef.cloud)
            echo "10.0.0.11 $2"
            ;;
          *)
            return 1
            ;;
        esac
      }

      When call update_ips_in_nodes_conf
      The status should be success
      # Should NOT print "Updating IP" for the peer since IP is already 10.0.0.11
      The output should not include "Updating IP for node"
    End
  End

  Describe "normalize_optional_config_values()"
    It "converts <nil> values to 0"
      FALKORDB_QUERY_MEM_CAPACITY="<nil>"
      FALKORDB_TIMEOUT_MAX="<nil>"
      FALKORDB_TIMEOUT_DEFAULT="<nil>"

      When call normalize_optional_config_values
      The status should be success
      The variable FALKORDB_QUERY_MEM_CAPACITY should eq "0"
      The variable FALKORDB_TIMEOUT_MAX should eq "0"
      The variable FALKORDB_TIMEOUT_DEFAULT should eq "0"
    End

    It "leaves numeric values unchanged"
      FALKORDB_QUERY_MEM_CAPACITY=100
      FALKORDB_TIMEOUT_MAX=200
      FALKORDB_TIMEOUT_DEFAULT=300

      When call normalize_optional_config_values
      The status should be success
      The variable FALKORDB_QUERY_MEM_CAPACITY should eq "100"
      The variable FALKORDB_TIMEOUT_MAX should eq "200"
      The variable FALKORDB_TIMEOUT_DEFAULT should eq "300"
    End
  End
End