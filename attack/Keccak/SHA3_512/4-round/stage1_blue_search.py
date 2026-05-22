from base_MILP.Keccak_MILP import *
from output.write_in_file_slice_64 import *

# Store all initial state solutions for each least_number
all_solutions = {}

for least_number in range(16, 20):
    add_constr = []
    solutions_list = []
    for search_number in range(3):
        print(f"\n=== Searching for blue bits >= {least_number} ===")

        model = gp.Model("Keccak_MILP_Automation")
        model.setParam('MIPGap', 0.0)
        model.setParam('MIPFocus', 2)
        model.setParam('PoolSolutions', 30)
        model.setParam('PoolGap', 0.0)

        # Initial state
        initial_state = [[[Bit(model, 'constant', 'uc') for x in range(5)] for y in range(5)] for z in range(64)]

        blue_bits = []
        for z in range(64):
            for x in range(4):
                if x == 3 and z >= 60:
                    continue
                initial_state[z][0][x] = Bit(model, f'initial_state[{z}][0][{x}]', (0, 0, '*', 0))
                initial_state[z][1][x] = Bit(model, f'initial_state[{z}][1][{x}]', (0, 0, 0, 0))
                initial_state[z][1][x].b = initial_state[z][0][x].b
                blue_bits.append(initial_state[z][0][x].b)

        for one_place, zero_place in add_constr:
            one_place_vars = []
            zero_place_vars = []
            for z, x in one_place:
                one_place_vars.append(initial_state[z][0][x].b)
            for z, x in zero_place:
                zero_place_vars.append(initial_state[z][0][x].b)
            model.addConstr(gp.quicksum(one_place_vars) <= len(one_place_vars) - 1)
        model.addConstr(gp.quicksum(blue_bits) <= 10)

        # First round theta (skip propagation)
        theta_state_1, C_1, D_1, theta_vars1 = create_first_theta_operation(model, initial_state, 'theta_1')

        for x in range(5):
            for z in range(64):
                model.addConstr(theta_vars1[f"C_x{x}_z{z}"]['delta_r'] == 0)
                model.addConstr(theta_vars1[f"C_x{x}_z{z}"]['delta_b'] == initial_state[z][0][x].b)
                model.addConstr(theta_vars1[f"D_x{x}_z{z}"]['delta_r'] == 0)
                model.addConstr(theta_vars1[f"D_x{x}_z{z}"]['delta_b'] == 0)

        for x in range(5):
            for y in range(5):
                for z in range(64):
                    model.addConstr(theta_vars1[f"new_z{z}_y{y}_x{x}"]['delta_r'] == 0)
                    model.addConstr(theta_vars1[f"new_z{z}_y{y}_x{x}"]['delta_b'] == 0)

        # First round rho and chi
        rho_state_1 = rho(theta_state_1)
        pi_state_1 = pi(rho_state_1)

        for z in range(64):
            for y in range(5):
                model.addConstr(pi_state_1[z][y][0].b + pi_state_1[z][y][1].b <= 1)

        # First round chi (skip propagation)
        theta_state_2, C_2, D_2, theta_vars2 = create_theta_operation(model, pi_state_1, 'theta_2')
        rho_state_2 = rho(theta_state_2)
        pi_state_2 = pi(rho_state_2)

        # Count diffusion bits
        diffusion_bit = []
        good_place = []
        adjacent_place = []

        model.addConstr(gp.quicksum(blue_bits) >= least_number)

        for x in range(5):
            for y in range(5):
                for z in range(64):
                    model.addConstr(theta_vars2[f"new_z{z}_y{y}_x{x}"]['delta_r'] == 0)
                    model.addConstr(theta_vars2[f"new_z{z}_y{y}_x{x}"]['delta_b'] == 0)
                    diffusion_bit.append(theta_state_2[z][y][x].b)
                    adjacent_bit = model.addVar(vtype=GRB.BINARY)
                    model.addConstr(adjacent_bit >= pi_state_2[z][y][x].b + pi_state_2[z][y][(x + 1) % 5].b - 1)
                    model.addConstr(2 * adjacent_bit <= pi_state_2[z][y][x].b + pi_state_2[z][y][(x + 1) % 5].b)
                    adjacent_place.append(adjacent_bit)
                    if (x, y) in [(0, 1), (1, 3)]:
                        good_place.append(pi_state_1[z][y][x].b)

        model.addConstr(gp.quicksum(diffusion_bit) - 0.1 * gp.quicksum(good_place) - 0.001 * gp.quicksum(adjacent_place), GRB.MINIMIZE)

        model.optimize()

        if model.status == GRB.OPTIMAL:
            num_solutions = model.SolCount
            print(f"Found {num_solutions} solutions")

            for sol_idx in range(num_solutions):
                model.setParam('SolutionNumber', sol_idx)

                # 64x5x5
                state_matrix = [[[0 for x in range(5)] for y in range(5)] for z in range(64)]

                for z in range(64):
                    for x in range(4):
                        # y=0, x=0-3
                        if isinstance(initial_state[z][0][x].b, gp.Var):
                            state_matrix[z][0][x] = int(initial_state[z][0][x].b.X)
                        else:
                            state_matrix[z][0][x] = int(initial_state[z][0][x].b)
                        # y=1, x=0-3 (same as y=0)
                        state_matrix[z][1][x] = state_matrix[z][0][x]

                solutions_list.append(state_matrix)

            temp_one = []
            temp_zero = []
            for z in range(64):
                for x in range(4):
                    if isinstance(initial_state[z][0][x].b, gp.Var):
                        b_value = int(initial_state[z][0][x].b.X)
                    else:
                        b_value = int(initial_state[z][0][x].b)
                    if b_value > 0.5:
                        temp_one.append((z, x))
                    else:
                        temp_zero.append((z, x))
            add_constr.append((temp_one, temp_zero))

    # Store all solutions for the current least_number
    all_solutions[least_number] = solutions_list

f = open(f"../blue_result/SHA3_512_all_blue.py", 'w')
f.write(f"all_solutions = {all_solutions}\n")
