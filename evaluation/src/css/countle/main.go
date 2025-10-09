package countle

type Operation struct {
	Op   string `json:"op"`
	Val1 int    `json:"val1"`
	Val2 int    `json:"val2"`
}

func Validate(operations []Operation, target int) bool {
	state := make(map[int]int)

	for _, num := range numbers {
		state[num] = 1
	}

	last := 0

	for _, op := range operations {
		if v1, exists := state[op.Val1]; !exists || v1 == 0 {
			return false
		}
		state[op.Val1]--
		if v2, exists := state[op.Val2]; !exists || v2 == 0 {
			return false
		}
		state[op.Val2]--
		res := 0
		switch op.Op {
		case "add":
			res = op.Val1 + op.Val2
		case "sub":
			res = op.Val1 - op.Val2
		case "mul":
			res = op.Val1 * op.Val2
		case "div":
			if op.Val2 == 0 || op.Val1%op.Val2 != 0 {
				return false
			}
			res = op.Val1 / op.Val2
		default:
			return false
		}
		if res < 0 {
			return false
		}
		if _, exists := state[res]; !exists {
			state[res] = 0
		}
		state[res] += 1
		last = res
	}

	return last == target
}
