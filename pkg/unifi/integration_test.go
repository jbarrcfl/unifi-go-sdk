//go:build integration

package unifi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPrefix = "sdk_integration_test_"

var (
	sharedClient     *NetworkClient
	sharedClientOnce sync.Once
	sharedClientErr  error
)

func init() {
	loadEnvFile(".env")
	loadEnvFile(filepath.Join("..", "..", ".env"))
}

func loadEnvFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}

func getSharedClient() (*NetworkClient, error) {
	sharedClientOnce.Do(func() {
		url := os.Getenv("UNIFI_NETWORK_URL")
		user := os.Getenv("UNIFI_NETWORK_USER")
		pass := os.Getenv("UNIFI_NETWORK_PASS")
		site := os.Getenv("UNIFI_NETWORK_SITE")

		if url == "" || user == "" || pass == "" {
			sharedClientErr = fmt.Errorf("missing required env vars")
			return
		}

		if site == "" {
			site = "default"
		}

		client, err := NewNetworkClient(NetworkClientConfig{
			BaseURL:            url,
			Site:               site,
			Username:           user,
			Password:           pass,
			InsecureSkipVerify: true,
			Timeout:            30 * time.Second,
		})
		if err != nil {
			sharedClientErr = err
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := client.Login(ctx); err != nil {
			sharedClientErr = err
			return
		}

		sharedClient = client
	})
	return sharedClient, sharedClientErr
}

func skipIfNoEnv(t *testing.T) *NetworkClient {
	t.Helper()

	url := os.Getenv("UNIFI_NETWORK_URL")
	user := os.Getenv("UNIFI_NETWORK_USER")
	pass := os.Getenv("UNIFI_NETWORK_PASS")

	if url == "" || user == "" || pass == "" {
		t.Skip("Skipping integration test: UNIFI_NETWORK_URL, UNIFI_NETWORK_USER, UNIFI_NETWORK_PASS not set")
	}

	client, err := getSharedClient()
	if err != nil {
		t.Fatalf("Failed to get shared client: %v", err)
	}

	return client
}

func testName(suffix string) string {
	return testPrefix + suffix
}

func cleanupTestResources(t *testing.T, client *NetworkClient, ctx context.Context) {
	t.Helper()

	networks, _ := client.ListNetworks(ctx)
	for _, n := range networks {
		if strings.HasPrefix(n.Name, testPrefix) {
			_ = client.DeleteNetwork(ctx, n.ID)
		}
	}

	fwRules, _ := client.ListFirewallRules(ctx)
	for _, r := range fwRules {
		if strings.HasPrefix(r.Name, testPrefix) {
			_ = client.DeleteFirewallRule(ctx, r.ID)
		}
	}

	fwGroups, _ := client.ListFirewallGroups(ctx)
	for _, g := range fwGroups {
		if strings.HasPrefix(g.Name, testPrefix) {
			_ = client.DeleteFirewallGroup(ctx, g.ID)
		}
	}

	portForwards, _ := client.ListPortForwards(ctx)
	for _, p := range portForwards {
		if strings.HasPrefix(p.Name, testPrefix) {
			_ = client.DeletePortForward(ctx, p.ID)
		}
	}

	wlans, _ := client.ListWLANs(ctx)
	for _, w := range wlans {
		if strings.HasPrefix(w.Name, testPrefix) {
			_ = client.DeleteWLAN(ctx, w.ID)
		}
	}

	portConfs, _ := client.ListPortConfs(ctx)
	for _, p := range portConfs {
		if strings.HasPrefix(p.Name, testPrefix) {
			_ = client.DeletePortConf(ctx, p.ID)
		}
	}

	routes, _ := client.ListRoutes(ctx)
	for _, r := range routes {
		if strings.HasPrefix(r.Name, testPrefix) {
			_ = client.DeleteRoute(ctx, r.ID)
		}
	}

	userGroups, _ := client.ListUserGroups(ctx)
	for _, u := range userGroups {
		if strings.HasPrefix(u.Name, testPrefix) {
			_ = client.DeleteUserGroup(ctx, u.ID)
		}
	}

	radiusProfiles, _ := client.ListRADIUSProfiles(ctx)
	for _, r := range radiusProfiles {
		if strings.HasPrefix(r.Name, testPrefix) {
			_ = client.DeleteRADIUSProfile(ctx, r.ID)
		}
	}

	ddns, _ := client.ListDynamicDNS(ctx)
	for _, d := range ddns {
		if strings.HasPrefix(d.HostName, testPrefix) {
			_ = client.DeleteDynamicDNS(ctx, d.ID)
		}
	}

	policies, _ := client.ListFirewallPolicies(ctx)
	for _, p := range policies {
		if strings.HasPrefix(p.Name, testPrefix) {
			_ = client.DeleteFirewallPolicy(ctx, p.ID)
		}
	}

	zones, _ := client.ListFirewallZones(ctx)
	for _, z := range zones {
		if strings.HasPrefix(z.Name, testPrefix) {
			_ = client.DeleteFirewallZone(ctx, z.ID)
		}
	}

	staticDNS, _ := client.ListStaticDNS(ctx)
	for _, s := range staticDNS {
		if strings.HasPrefix(s.Key, testPrefix) {
			_ = client.DeleteStaticDNS(ctx, s.ID)
		}
	}

	trafficRules, _ := client.ListTrafficRules(ctx)
	for _, tr := range trafficRules {
		if strings.HasPrefix(tr.Name, testPrefix) {
			_ = client.DeleteTrafficRule(ctx, tr.ID)
		}
	}

	trafficRoutes, _ := client.ListTrafficRoutes(ctx)
	for _, tr := range trafficRoutes {
		if strings.HasPrefix(tr.Name, testPrefix) {
			_ = client.DeleteTrafficRoute(ctx, tr.ID)
		}
	}

	natRules, _ := client.ListNatRules(ctx)
	for _, n := range natRules {
		if strings.HasPrefix(n.Description, testPrefix) {
			_ = client.DeleteNatRule(ctx, n.ID)
		}
	}
}

func TestIntegration_Authentication(t *testing.T) {
	client := skipIfNoEnv(t)

	if !client.IsLoggedIn() {
		t.Error("Expected client to be logged in after setup")
	}

	// Note: We don't test logout/re-login with the shared client
	// as it would affect other tests. The login flow is tested
	// implicitly by the shared client initialization.
	t.Log("Shared client is logged in successfully")
}

func TestIntegration_Networks_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("network")
	vlan := 3999

	network := &Network{
		Name:         name,
		Purpose:      "corporate",
		VLAN:         &vlan,
		VLANEnabled:  BoolPtr(true),
		IPSubnet:     "10.199.99.1/24",
		DHCPDEnabled: BoolPtr(true),
		DHCPDStart:   "10.199.99.100",
		DHCPDStop:    "10.199.99.200",
		Enabled:      BoolPtr(true),
	}

	created, err := client.CreateNetwork(ctx, network)
	if err != nil {
		t.Fatalf("CreateNetwork failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created network has no ID")
	}
	if created.Name != name {
		t.Errorf("Expected name %q, got %q", name, created.Name)
	}

	fetched, err := client.GetNetwork(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetNetwork failed: %v", err)
	}
	if fetched.ID != created.ID {
		t.Errorf("Expected ID %q, got %q", created.ID, fetched.ID)
	}

	list, err := client.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks failed: %v", err)
	}
	found := false
	for _, n := range list {
		if n.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created network not found in list")
	}

	fetched.DHCPDStart = "10.199.99.50"
	updated, err := client.UpdateNetwork(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateNetwork failed: %v", err)
	}
	if updated.DHCPDStart != "10.199.99.50" {
		t.Errorf("Expected DHCPDStart %q, got %q", "10.199.99.50", updated.DHCPDStart)
	}

	if err := client.DeleteNetwork(ctx, created.ID); err != nil {
		t.Fatalf("DeleteNetwork failed: %v", err)
	}

	_, err = client.GetNetwork(ctx, created.ID)
	if err == nil {
		t.Error("Expected error getting deleted network")
	}
}

func TestIntegration_FirewallGroups_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("fwgroup")
	group := &FirewallGroup{
		Name:         name,
		GroupType:    "address-group",
		GroupMembers: []string{"192.168.100.0/24", "192.168.101.0/24"},
	}

	created, err := client.CreateFirewallGroup(ctx, group)
	if err != nil {
		t.Fatalf("CreateFirewallGroup failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created group has no ID")
	}

	fetched, err := client.GetFirewallGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetFirewallGroup failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListFirewallGroups(ctx)
	if err != nil {
		t.Fatalf("ListFirewallGroups failed: %v", err)
	}
	found := false
	for _, g := range list {
		if g.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created group not found in list")
	}

	fetched.GroupMembers = append(fetched.GroupMembers, "192.168.102.0/24")
	updated, err := client.UpdateFirewallGroup(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateFirewallGroup failed: %v", err)
	}
	if len(updated.GroupMembers) != 3 {
		t.Errorf("Expected 3 members, got %d", len(updated.GroupMembers))
	}

	if err := client.DeleteFirewallGroup(ctx, created.ID); err != nil {
		t.Fatalf("DeleteFirewallGroup failed: %v", err)
	}
}

func TestIntegration_FirewallRules_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("fwrule")
	rule := &FirewallRule{
		Name:                  name,
		Enabled:               BoolPtr(true),
		Ruleset:               "WAN_LOCAL",
		RuleIndex:             IntPtr(4000),
		Action:                "drop",
		Protocol:              "tcp",
		ProtocolMatchExcepted: BoolPtr(false),
		SrcFirewallGroupIDs:   []string{},
		SrcAddress:            "",
		SrcNetworkConfType:    "NETv4",
		DstFirewallGroupIDs:   []string{},
		DstAddress:            "",
		DstNetworkConfType:    "NETv4",
		DstPort:               "22",
	}

	created, err := client.CreateFirewallRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateFirewallRule failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created rule has no ID")
	}

	fetched, err := client.GetFirewallRule(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetFirewallRule failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListFirewallRules(ctx)
	if err != nil {
		t.Fatalf("ListFirewallRules failed: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created rule not found in list")
	}

	fetched.DstPort = "2222"
	updated, err := client.UpdateFirewallRule(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateFirewallRule failed: %v", err)
	}
	if updated.DstPort != "2222" {
		t.Errorf("Expected DstPort %q, got %q", "2222", updated.DstPort)
	}

	if err := client.DeleteFirewallRule(ctx, created.ID); err != nil {
		t.Fatalf("DeleteFirewallRule failed: %v", err)
	}
}

func TestIntegration_PortForwards_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("portfwd")
	pf := &PortForward{
		Name:          name,
		Enabled:       BoolPtr(true),
		PfwdInterface: "wan",
		Proto:         "tcp",
		DstPort:       "8080",
		Fwd:           "192.168.1.100",
		FwdPort:       "80",
	}

	created, err := client.CreatePortForward(ctx, pf)
	if err != nil {
		t.Fatalf("CreatePortForward failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created port forward has no ID")
	}

	fetched, err := client.GetPortForward(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetPortForward failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListPortForwards(ctx)
	if err != nil {
		t.Fatalf("ListPortForwards failed: %v", err)
	}
	found := false
	for _, p := range list {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created port forward not found in list")
	}

	fetched.FwdPort = "8081"
	updated, err := client.UpdatePortForward(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdatePortForward failed: %v", err)
	}
	if updated.FwdPort != "8081" {
		t.Errorf("Expected FwdPort %q, got %q", "8081", updated.FwdPort)
	}

	if err := client.DeletePortForward(ctx, created.ID); err != nil {
		t.Fatalf("DeletePortForward failed: %v", err)
	}
}

func TestIntegration_UserGroups_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("usergroup")
	downRate := 10000
	upRate := 5000

	ug := &UserGroup{
		Name:           name,
		QosRateMaxDown: &downRate,
		QosRateMaxUp:   &upRate,
	}

	created, err := client.CreateUserGroup(ctx, ug)
	if err != nil {
		t.Fatalf("CreateUserGroup failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created user group has no ID")
	}

	fetched, err := client.GetUserGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUserGroup failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListUserGroups(ctx)
	if err != nil {
		t.Fatalf("ListUserGroups failed: %v", err)
	}
	found := false
	for _, u := range list {
		if u.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created user group not found in list")
	}

	newDown := 20000
	fetched.QosRateMaxDown = &newDown
	updated, err := client.UpdateUserGroup(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateUserGroup failed: %v", err)
	}
	if updated.QosRateMaxDown == nil || *updated.QosRateMaxDown != 20000 {
		t.Error("Expected QosRateMaxDown to be 20000")
	}

	if err := client.DeleteUserGroup(ctx, created.ID); err != nil {
		t.Fatalf("DeleteUserGroup failed: %v", err)
	}
}

func TestIntegration_Routes_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("route")
	distance := 1

	route := &Routing{
		Name:                name,
		Enabled:             BoolPtr(true),
		Type:                "static-route",
		StaticRouteType:     "nexthop-route",
		StaticRouteNetwork:  "10.200.0.0/24",
		StaticRouteNexthop:  "192.168.1.1",
		StaticRouteDistance: &distance,
	}

	created, err := client.CreateRoute(ctx, route)
	if err != nil {
		t.Fatalf("CreateRoute failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created route has no ID")
	}

	fetched, err := client.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created route not found in list")
	}

	fetched.StaticRouteNetwork = "10.201.0.0/24"
	updated, err := client.UpdateRoute(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateRoute failed: %v", err)
	}
	if updated.StaticRouteNetwork != "10.201.0.0/24" {
		t.Errorf("Expected StaticRouteNetwork %q, got %q", "10.201.0.0/24", updated.StaticRouteNetwork)
	}

	if err := client.DeleteRoute(ctx, created.ID); err != nil {
		t.Fatalf("DeleteRoute failed: %v", err)
	}
}

func TestIntegration_PortConfs_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("portconf")
	profile := &PortConf{
		Name:    name,
		Forward: "all",
	}

	created, err := client.CreatePortConf(ctx, profile)
	if err != nil {
		t.Fatalf("CreatePortConf failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created port conf has no ID")
	}

	fetched, err := client.GetPortConf(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetPortConf failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListPortConfs(ctx)
	if err != nil {
		t.Fatalf("ListPortConfs failed: %v", err)
	}
	found := false
	for _, p := range list {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created port conf not found in list")
	}

	newName := testName("portconf_updated")
	fetched.Name = newName
	updated, err := client.UpdatePortConf(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdatePortConf failed: %v", err)
	}
	if updated.ID != fetched.ID {
		t.Errorf("Expected ID %q, got %q", fetched.ID, updated.ID)
	}

	if err := client.DeletePortConf(ctx, created.ID); err != nil {
		t.Fatalf("DeletePortConf failed: %v", err)
	}
}

func TestIntegration_RADIUSProfiles_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("radius")
	port := 1812

	profile := &RADIUSProfile{
		Name:             name,
		UseUsgAuthServer: BoolPtr(false),
		UseUsgAcctServer: BoolPtr(false),
		AuthServers: []RADIUSServer{
			{
				IP:      "192.168.1.10",
				Port:    &port,
				XSecret: "testsecret",
			},
		},
	}

	created, err := client.CreateRADIUSProfile(ctx, profile)
	if err != nil {
		t.Fatalf("CreateRADIUSProfile failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created RADIUS profile has no ID")
	}

	fetched, err := client.GetRADIUSProfile(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRADIUSProfile failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListRADIUSProfiles(ctx)
	if err != nil {
		t.Fatalf("ListRADIUSProfiles failed: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created RADIUS profile not found in list")
	}

	if len(fetched.AuthServers) > 0 {
		newPort := 1813
		fetched.AuthServers[0].Port = &newPort
	}
	updated, err := client.UpdateRADIUSProfile(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateRADIUSProfile failed: %v", err)
	}
	if len(updated.AuthServers) > 0 && updated.AuthServers[0].Port != nil && *updated.AuthServers[0].Port != 1813 {
		t.Error("Expected auth server port to be 1813")
	}

	if err := client.DeleteRADIUSProfile(ctx, created.ID); err != nil {
		t.Fatalf("DeleteRADIUSProfile failed: %v", err)
	}
}

func TestIntegration_V2_FirewallZones_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("zone")
	zone := &FirewallZone{
		Name: name,
	}

	created, err := client.CreateFirewallZone(ctx, zone)
	if err != nil {
		if errors.Is(err, ErrServerError) {
			t.Skip("FirewallZone creation not supported on this controller")
		}
		t.Fatalf("CreateFirewallZone failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created zone has no ID")
	}

	fetched, err := client.GetFirewallZone(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetFirewallZone failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListFirewallZones(ctx)
	if err != nil {
		t.Fatalf("ListFirewallZones failed: %v", err)
	}
	found := false
	for _, z := range list {
		if z.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created zone not found in list")
	}

	newName := testName("zone_updated")
	fetched.Name = newName
	updated, err := client.UpdateFirewallZone(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateFirewallZone failed: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("Expected name %q, got %q", newName, updated.Name)
	}

	if err := client.DeleteFirewallZone(ctx, created.ID); err != nil {
		t.Fatalf("DeleteFirewallZone failed: %v", err)
	}
}

func TestIntegration_V2_FirewallPolicies_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	zones, err := client.ListFirewallZones(ctx)
	if err != nil {
		t.Fatalf("ListFirewallZones failed: %v", err)
	}
	if len(zones) < 2 {
		t.Skip("Need at least 2 zones for policy test")
	}

	name := testName("policy")
	policy := &FirewallPolicy{
		Name:    name,
		Enabled: BoolPtr(true),
		Action:  "BLOCK",
		Source: &PolicyEndpoint{
			ZoneID:         zones[0].ID,
			MatchingTarget: "ANY",
		},
		Destination: &PolicyEndpoint{
			ZoneID:         zones[1].ID,
			MatchingTarget: "ANY",
		},
	}

	created, err := client.CreateFirewallPolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreateFirewallPolicy failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created policy has no ID")
	}

	fetched, err := client.GetFirewallPolicy(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetFirewallPolicy failed: %v", err)
	}
	if fetched.Name != name {
		t.Errorf("Expected name %q, got %q", name, fetched.Name)
	}

	list, err := client.ListFirewallPolicies(ctx)
	if err != nil {
		t.Fatalf("ListFirewallPolicies failed: %v", err)
	}
	found := false
	for _, p := range list {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created policy not found in list")
	}

	fetched.Action = "ALLOW"
	updated, err := client.UpdateFirewallPolicy(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateFirewallPolicy failed: %v", err)
	}
	if updated.Action != "ALLOW" {
		t.Errorf("Expected Action %q, got %q", "ALLOW", updated.Action)
	}

	if err := client.DeleteFirewallPolicy(ctx, created.ID); err != nil {
		t.Fatalf("DeleteFirewallPolicy failed: %v", err)
	}
}

func TestIntegration_V2_StaticDNS_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	key := testName("dns.local")
	record := &StaticDNS{
		Key:        key,
		Value:      "192.168.1.100",
		RecordType: "A",
		Enabled:    BoolPtr(true),
	}

	created, err := client.CreateStaticDNS(ctx, record)
	if err != nil {
		t.Fatalf("CreateStaticDNS failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created DNS record has no ID")
	}

	fetched, err := client.GetStaticDNS(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetStaticDNS failed: %v", err)
	}
	if fetched.Key != key {
		t.Errorf("Expected key %q, got %q", key, fetched.Key)
	}

	list, err := client.ListStaticDNS(ctx)
	if err != nil {
		t.Fatalf("ListStaticDNS failed: %v", err)
	}
	found := false
	for _, s := range list {
		if s.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created DNS record not found in list")
	}

	fetched.Value = "192.168.1.101"
	updated, err := client.UpdateStaticDNS(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateStaticDNS failed: %v", err)
	}
	if updated.Value != "192.168.1.101" {
		t.Errorf("Expected Value %q, got %q", "192.168.1.101", updated.Value)
	}

	if err := client.DeleteStaticDNS(ctx, created.ID); err != nil {
		t.Fatalf("DeleteStaticDNS failed: %v", err)
	}
}

func TestIntegration_V2_TrafficRules_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	name := testName("trafficrule")
	rule := &TrafficRule{
		Name:           name,
		Enabled:        BoolPtr(true),
		Action:         "BLOCK",
		MatchingTarget: "DOMAIN",
		Domains:        []TrafficDomain{{Domain: "blocked-domain.example.com"}},
		TargetDevices: []TrafficRuleTarget{
			{Type: "ALL_CLIENTS"},
		},
	}

	created, err := client.CreateTrafficRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateTrafficRule failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created traffic rule has no ID")
	}

	fetched, err := client.GetTrafficRule(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTrafficRule failed: %v", err)
	}
	if fetched.ID != created.ID {
		t.Errorf("Expected ID %q, got %q", created.ID, fetched.ID)
	}

	list, err := client.ListTrafficRules(ctx)
	if err != nil {
		t.Fatalf("ListTrafficRules failed: %v", err)
	}
	found := false
	for _, tr := range list {
		if tr.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created traffic rule not found in list")
	}

	fetched.Domains = []TrafficDomain{{Domain: "blocked-domain.example.com"}, {Domain: "another-blocked.example.com"}}
	updated, err := client.UpdateTrafficRule(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateTrafficRule failed: %v", err)
	}
	if len(updated.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(updated.Domains))
	}

	if err := client.DeleteTrafficRule(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTrafficRule failed: %v", err)
	}
}

func TestIntegration_V2_TrafficRoutes_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	networks, err := client.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks failed: %v", err)
	}
	var wanNetworkID string
	for _, n := range networks {
		if n.Purpose == "wan" {
			wanNetworkID = n.ID
			break
		}
	}
	if wanNetworkID == "" {
		t.Skip("No WAN network found for traffic route test")
	}

	name := testName("trafficroute")
	route := &TrafficRoute{
		Name:           name,
		Enabled:        BoolPtr(true),
		MatchingTarget: "DOMAIN",
		Domains:        []TrafficDomain{{Domain: "route-domain.example.com"}},
		NetworkID:      wanNetworkID,
		TargetDevices: []TrafficRuleTarget{
			{Type: "ALL_CLIENTS"},
		},
	}

	created, err := client.CreateTrafficRoute(ctx, route)
	if err != nil {
		t.Fatalf("CreateTrafficRoute failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created traffic route has no ID")
	}

	fetched, err := client.GetTrafficRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTrafficRoute failed: %v", err)
	}
	if fetched.ID != created.ID {
		t.Errorf("Expected ID %q, got %q", created.ID, fetched.ID)
	}

	list, err := client.ListTrafficRoutes(ctx)
	if err != nil {
		t.Fatalf("ListTrafficRoutes failed: %v", err)
	}
	found := false
	for _, tr := range list {
		if tr.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created traffic route not found in list")
	}

	fetched.Domains = []TrafficDomain{{Domain: "route-domain.example.com"}, {Domain: "another-route.example.com"}}
	updated, err := client.UpdateTrafficRoute(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateTrafficRoute failed: %v", err)
	}
	if len(updated.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(updated.Domains))
	}

	if err := client.DeleteTrafficRoute(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTrafficRoute failed: %v", err)
	}
}

func TestIntegration_V2_NatRules_CRUD(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	desc := testName("natrule")
	rule := &NatRule{
		Enabled:     BoolPtr(true),
		Type:        "MASQUERADE",
		Description: desc,
		Protocol:    "all",
	}

	created, err := client.CreateNatRule(ctx, rule)
	if err != nil {
		if errors.Is(err, ErrBadRequest) || errors.Is(err, ErrServerError) {
			t.Skip("NAT rules API not fully supported on this controller")
		}
		t.Fatalf("CreateNatRule failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Created NAT rule has no ID")
	}

	fetched, err := client.GetNatRule(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetNatRule failed: %v", err)
	}
	if fetched.Description != desc {
		t.Errorf("Expected description %q, got %q", desc, fetched.Description)
	}

	list, err := client.ListNatRules(ctx)
	if err != nil {
		t.Fatalf("ListNatRules failed: %v", err)
	}
	found := false
	for _, n := range list {
		if n.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created NAT rule not found in list")
	}

	newDesc := testName("natrule_updated")
	fetched.Description = newDesc
	updated, err := client.UpdateNatRule(ctx, fetched.ID, fetched)
	if err != nil {
		t.Fatalf("UpdateNatRule failed: %v", err)
	}
	if updated.Description != newDesc {
		t.Errorf("Expected Description %q, got %q", newDesc, updated.Description)
	}

	if err := client.DeleteNatRule(ctx, created.ID); err != nil {
		t.Fatalf("DeleteNatRule failed: %v", err)
	}
}

func TestIntegration_V2_ReadOnlyEndpoints(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Run("ListActiveClients", func(t *testing.T) {
		clients, err := client.ListActiveClients(ctx)
		if err != nil {
			t.Errorf("ListActiveClients failed: %v", err)
		}
		t.Logf("Found %d active clients", len(clients))
	})

	t.Run("ListNetworkDevices", func(t *testing.T) {
		devices, err := client.ListNetworkDevices(ctx)
		if err != nil {
			t.Errorf("ListNetworkDevices failed: %v", err)
		}
		t.Logf("Found %d network devices", len(devices.NetworkDevices))
	})

	t.Run("ListAclRules", func(t *testing.T) {
		rules, err := client.ListAclRules(ctx)
		if err != nil {
			t.Errorf("ListAclRules failed: %v", err)
		}
		t.Logf("Found %d ACL rules", len(rules))
	})

	t.Run("ListQosRules", func(t *testing.T) {
		rules, err := client.ListQosRules(ctx)
		if err != nil {
			t.Errorf("ListQosRules failed: %v", err)
		}
		t.Logf("Found %d QoS rules", len(rules))
	})

	t.Run("GetContentFiltering", func(t *testing.T) {
		cf, err := client.GetContentFiltering(ctx)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				t.Log("Content filtering not configured on this controller")
				return
			}
			t.Errorf("GetContentFiltering failed: %v", err)
		}
		if cf != nil {
			t.Logf("Content filtering enabled: %v", cf.Enabled)
		}
	})

	t.Run("ListVpnConnections", func(t *testing.T) {
		vpns, err := client.ListVpnConnections(ctx)
		if err != nil {
			t.Errorf("ListVpnConnections failed: %v", err)
		}
		t.Logf("Found %d VPN connections", len(vpns))
	})

	t.Run("ListWanSlas", func(t *testing.T) {
		slas, err := client.ListWanSlas(ctx)
		if err != nil {
			t.Errorf("ListWanSlas failed: %v", err)
		}
		t.Logf("Found %d WAN SLAs", len(slas))
	})
}

func TestIntegration_ErrorHandling(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Run("GetNonExistent", func(t *testing.T) {
		_, err := client.GetNetwork(ctx, "nonexistent-id-12345")
		if err == nil {
			t.Error("Expected error for non-existent network")
		}
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		err := client.DeleteNetwork(ctx, "nonexistent-id-12345")
		if err == nil {
			t.Error("Expected error for deleting non-existent network")
		}
	})

	t.Run("CreateInvalid", func(t *testing.T) {
		network := &Network{
			Name:     "",
			IPSubnet: "invalid-subnet",
		}
		_, err := client.CreateNetwork(ctx, network)
		if err == nil {
			t.Error("Expected error for invalid network")
		}
	})
}

func TestIntegration_ConcurrentOperations(t *testing.T) {
	client := skipIfNoEnv(t)
	ctx := context.Background()

	t.Cleanup(func() {
		cleanupTestResources(t, client, ctx)
	})

	const numGroups = 5
	errChan := make(chan error, numGroups)
	idChan := make(chan string, numGroups)

	for i := 0; i < numGroups; i++ {
		go func(idx int) {
			name := fmt.Sprintf("%sconcurrent_%d", testPrefix, idx)
			group := &FirewallGroup{
				Name:         name,
				GroupType:    "port-group",
				GroupMembers: []string{fmt.Sprintf("%d", 8000+idx)},
			}
			created, err := client.CreateFirewallGroup(ctx, group)
			if err != nil {
				errChan <- err
				return
			}
			idChan <- created.ID
			errChan <- nil
		}(i)
	}

	var createdIDs []string
	for i := 0; i < numGroups; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Concurrent create failed: %v", err)
		}
	}
	close(idChan)
	for id := range idChan {
		createdIDs = append(createdIDs, id)
	}

	if len(createdIDs) != numGroups {
		t.Errorf("Expected %d groups created, got %d", numGroups, len(createdIDs))
	}

	for _, id := range createdIDs {
		if err := client.DeleteFirewallGroup(ctx, id); err != nil {
			t.Errorf("Failed to delete group %s: %v", id, err)
		}
	}
}
