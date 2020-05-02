package sig

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewConfig(t *testing.T) {
	tcs := []struct {
		in   string
		keys []Key
	}{
		{
			`
keys:
  - pubkey: RWT1JFtHhbzLGdmcmtwCC/2sUjK2mDKuHkcvS4yXbKHZAhGd/DuGLNqi
    sha256:
      - hash: 99e3dc1f9cda82ed274a94b5e59d6c6c43315e60e8fd4cc86e4ef496e7cdf7dc
      - hash: 1a7c801e11f797c95dafdeb6fc003a628143dcd4525611f8e006ec901eceaf68
  - pubkey: RWSPK7F+TwZRwilJLz0tAnfYriQH3Sukr3JY2MHXa7aIPVmNKfSl0m0K
    sha256:
      - hash: 300b95dd5813bd8daea8fab5ea9d08b8ab43540f5e5195173043af7b6f03cabe
      - hash: 35fabda57fc83f3ee8e2fd55c01b3b8f4293fb32068bcb109e30d72e1211a788
`,
			[]Key{
				{
					Pubkey: "RWT1JFtHhbzLGdmcmtwCC/2sUjK2mDKuHkcvS4yXbKHZAhGd/DuGLNqi",
					Sha256: []AllowedItem{
						{Hash: "99e3dc1f9cda82ed274a94b5e59d6c6c43315e60e8fd4cc86e4ef496e7cdf7dc"},
						{Hash: "1a7c801e11f797c95dafdeb6fc003a628143dcd4525611f8e006ec901eceaf68"},
					},
				}, {
					Pubkey: "RWSPK7F+TwZRwilJLz0tAnfYriQH3Sukr3JY2MHXa7aIPVmNKfSl0m0K",
					Sha256: []AllowedItem{
						{Hash: "300b95dd5813bd8daea8fab5ea9d08b8ab43540f5e5195173043af7b6f03cabe"},
						{Hash: "35fabda57fc83f3ee8e2fd55c01b3b8f4293fb32068bcb109e30d72e1211a788"},
					},
				},
			},
		},
	}

	for i, tc := range tcs {
		c, err := NewConfig([]byte(tc.in))
		if err != nil {
			t.Errorf("TestNewConfig %d: err: %v", i, err)
			continue
		}
		if !cmp.Equal(c.Keys, tc.keys) {
			t.Errorf("TestNewConfig %d: unequal with:\n%s\n", i, cmp.Diff(c.Keys, tc.keys))
		}
	}
}
