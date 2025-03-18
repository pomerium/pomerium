package ssh

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestSSH(t *testing.T) {
	// generate client ssh key
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	// ssh client setup
	clientConfig := &ssh.ClientConfig{
		User: "demo",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// pomerium + upstream setup
	env := testenv.New(t)

	up := upstreams.SSH()
	r := up.Route().
		From(env.SubdomainURLWithScheme("ssh", "ssh")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })
	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	// test scenario -- first verify that the upstream is working at all
	client, err := up.DirectDial(r, clientConfig)
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()
}

func TestHelloWorld(t *testing.T) {
	t.Skip("debugging...")

	key, err := os.ReadFile("/Users/kjenkins/scratch/sshd/demo_key")
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(key)
	require.NoError(t, err)

	config := &ssh.ClientConfig{
		User: "demo",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", "localhost:2222", config)
	require.NoError(t, err, "unable to connect")
	defer conn.Close()

	//conn.ServerVersion()

	sess, err := conn.NewSession()
	require.NoError(t, err, "unable to start session")
	defer sess.Close()

	var output bytes.Buffer
	sess.Stdout = &output
	sess.Stdin = strings.NewReader("whoami\n")

	err = sess.Shell()

	fmt.Println("Shell() returned ", err)

	err = sess.Wait()

	fmt.Println("Wait() returned ", err)

	fmt.Println(" --> output:\n\n", output.String())

	//sess.SendRequest()
}
