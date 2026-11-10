package manifest

import "sort"

// Sort orders units by the manifest sort key of §2:
//
//	(root_index, profile, entry_id, path_key, part_id)
//
// part_id defaults to "" and therefore sorts first. All sub-keys use byte
// order. Sort is stable, so records that compare equal keep their input order.
//
// root_index comes from Unit.RootIndex, the in-memory position of the unit's
// root in the header roots array. Use SortWithRoots to fill it from a header;
// units left at the zero value are ordered by root name to keep the result
// deterministic when no header is available.
func Sort(units []Unit) {
	sort.SliceStable(units, func(i, j int) bool {
		a, b := &units[i], &units[j]
		if a.RootIndex != b.RootIndex {
			return a.RootIndex < b.RootIndex
		}
		if a.Root != b.Root {
			return a.Root < b.Root
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		if a.Entry != b.Entry {
			return a.Entry < b.Entry
		}
		if a.PathKey != b.PathKey {
			return a.PathKey < b.PathKey
		}
		return a.PartID < b.PartID
	})
}

// SortWithRoots assigns each unit's RootIndex from the header roots order and
// then sorts. Units whose root is not declared get the next index after the
// last declared root (and are ordered by root name among themselves).
func SortWithRoots(units []Unit, roots []Root) {
	index := make(map[string]int, len(roots))
	for i, r := range roots {
		if _, ok := index[r.Name]; !ok {
			index[r.Name] = i
		}
	}
	for i := range units {
		if n, ok := index[units[i].Root]; ok {
			units[i].RootIndex = n
		} else {
			units[i].RootIndex = len(roots)
		}
	}
	Sort(units)
}
