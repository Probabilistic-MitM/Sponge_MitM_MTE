import gurobipy as gp
from gurobipy import GRB
from base_MILP.Keccak_MILP_32 import *
from output.write_in_file_slice_32 import *
from attack.Keccak.SHA3_512.blue_result.SHA3_512_all_blue import all_solutions

# Traverse all solutions
for key in all_solutions.keys():
    key_number = -1  # Scheme number

    # Traverse each solution
    for blue_scheme in all_solutions[key]:
        key_number += 1

        print(f"Initial number {key}")

        # Create Gurobi model
        model = gp.Model("Keccak_MILP_Automation")
        model.setParam('MIPFocus', 1)
        # model.setParam('TimeLimit', 30000)

        # Initialize state
        print("Initializing Keccak state...")

        # Create 5x5x32 initial state
        initial_state = [[[Bit(model, 'constant', 'uc') for x in range(5)] for y in range(5)] for z in range(32)]

        num_rounds = 4  # Number of rounds - 1

        # Initialize state bits
        for z in range(32):
            for x in range(4):
                if x == 3 and z >= 28:  # Skip specific positions
                    continue
                if blue_scheme[z][0][x] < 0.5:
                    # Set as red bit
                    initial_state[z][0][x].b = 0
                    initial_state[z][0][x].r = model.addVar(vtype=GRB.BINARY, name=f"inital_{z}_{0}_{x}_r")
                    # Row y=1 same as row y=0
                    initial_state[z][1][x].b = initial_state[z][0][x].b
                    initial_state[z][1][x].r = initial_state[z][0][x].r
                else:
                    # Set as blue bit
                    initial_state[z][0][x].r = 0
                    initial_state[z][0][x].b = 1
                    # Row y=1 same as row y=0
                    initial_state[z][1][x].b = initial_state[z][0][x].b
                    initial_state[z][1][x].r = initial_state[z][0][x].r

        # Apply round functions
        print("Applying round functions...")

        # Save intermediate states
        intermediate_states = []
        current_state = initial_state

        # Apply multiple rounds
        for round_num in range(num_rounds):
            print(f"Applying round {round_num + 1}")

            # Theta operation
            print(f"  Round {round_num + 1}: Theta operation")
            # Choose different Theta operation implementation based on round number
            if round_num == 0:
                theta_state, C, D, theta_vars = create_first_theta_operation(model, current_state, f"round{round_num}_theta")
            elif round_num == 1:
                theta_state, C, D, theta_vars = create_second_theta_operation(model, current_state, f"round{round_num}_theta")
            else:
                theta_state, C, D, theta_vars = create_theta_operation(model, current_state, f"round{round_num}_theta")

            # Rho operation
            print(f"  Round {round_num + 1}: Rho operation")
            rho_state = rho(theta_state)

            # Pi operation
            print(f"  Round {round_num + 1}: Pi operation")
            pi_state = pi(rho_state)

            # Chi operation
            print(f"  Round {round_num + 1}: Chi operation")
            # Choose different Chi operation implementation based on round number
            if round_num == 0:
                chi_state, chi_vars = create_first_chi_operation_512(model, pi_state, f"round{round_num}_chi")
            elif round_num == 1:
                chi_state, chi_vars = create_second_chi_operation(model, pi_state, f"round{round_num}_chi")
            else:
                chi_state, chi_vars = create_chi_operation(model, pi_state, f"round{round_num}_chi")

            # Save current round state
            intermediate_states.append({
                'theta': theta_state,
                'C': C,
                'D': D,
                'theta_var': theta_vars,
                'rho_west': rho_state,
                'chi': pi_state,
                'rho_east': chi_state,
                'chi_var': chi_vars
            })

            # Update current state
            current_state = chi_state

        final_state = current_state
        print(f"Completed {num_rounds} rounds application")

        # Calculate equation count and variable statistics
        print("Calculating equation count...")

        # Count variable types in initial state
        red_vars_count = gp.quicksum(initial_state[z][y][x].r for z in range(32) for y in range(5) for x in range(5))
        blue_vars_count = gp.quicksum(initial_state[z][y][x].b for z in range(32) for y in range(5) for x in range(5))

        # Count intervention variables in round functions
        delta_total_r = 0
        delta_total_b = 0
        sum_const_cond = 0
        sum_quad = 0

        # Traverse intermediate states, count variables
        for round_state in intermediate_states:
            theta_vars = round_state['theta_var']
            # Count variables in Theta operation
            for z in range(32):
                for x in range(5):
                    delta_total_r += theta_vars[f"C_x{x}_z{z}"]['delta_r']
                    delta_total_b += theta_vars[f"C_x{x}_z{z}"]['delta_b']
                    sum_const_cond += theta_vars[f"C_x{x}_z{z}"]['new_cond']

                    delta_total_r += theta_vars[f"D_x{x}_z{z}"]['delta_r']
                    delta_total_b += theta_vars[f"D_x{x}_z{z}"]['delta_b']
                    sum_const_cond += theta_vars[f"D_x{x}_z{z}"]['new_cond']

                    for y in range(5):
                        delta_total_r += theta_vars[f"new_z{z}_y{y}_x{x}"]['delta_r']
                        delta_total_b += theta_vars[f"new_z{z}_y{y}_x{x}"]['delta_b']
                        sum_const_cond += theta_vars[f"new_z{z}_y{y}_x{x}"]['new_cond']

            # Count variables in Chi operation
            chi_vars = round_state['chi_var']
            for z in range(32):
                for y in range(5):
                    for x in range(5):
                        delta_total_r += chi_vars[f"new_z{z}_y{y}_x{x}"]['delta_r']
                        delta_total_b += chi_vars[f"new_z{z}_y{y}_x{x}"]['delta_b']
                        sum_const_cond += chi_vars[f"new_z{z}_y{y}_x{x}"]['new_cond']
                        sum_quad += chi_vars[f"and_z{z}_y{y}_x{x}"]['CT']

        # Add constraints
        model.addConstr(sum_quad <= 3)  # Non-linear constraint limit
        model.addConstr(blue_vars_count - delta_total_b <= 5)  # Blue variable constraint

        # Calculate hash output bits
        hash_output_bits = []  # Hash output bits
        cut_bits = []  # The damage of probability paths to red blue sets

        # Process each z value
        for z in range(32):
            # Equation 3 constraints
            equation3 = model.addVar(vtype=GRB.BINARY, name=f'equation3_{z}')
            model.addConstr(equation3 <= 1 - final_state[z][0][3].ul + final_state[z][0][3].r + final_state[z][0][3].b)
            model.addConstr(equation3 <= 1 - final_state[z][3][3].ul + final_state[z][3][3].r + final_state[z][3][3].b)
            hash_output_bits.append(0.58 * equation3)
            cut_bits.append(0.42 * equation3)

            # Equation 4 constraints
            equation4 = model.addVar(vtype=GRB.BINARY, name=f'equation4_{z}')
            model.addConstr(equation4 <= 1 - final_state[z][1][4].ul + final_state[z][1][4].r + final_state[z][1][4].b)
            model.addConstr(equation4 <= 1 - final_state[z][4][4].ul + final_state[z][4][4].r + final_state[z][4][4].b)
            hash_output_bits.append(0.58 * equation4)
            cut_bits.append(0.42 * equation4)

        # Total equations
        total_equations = gp.quicksum(hash_output_bits)
        print("Equation calculation completed")

        # Set constraints and objective function
        print("Setting constraints and objective function...")

        # Attack complexity variable
        temp_degree = model.addVar(vtype=GRB.CONTINUOUS, lb=0, name='complexity')

        # Attack complexity constraints
        model.addConstr(temp_degree <= red_vars_count - delta_total_r - gp.quicksum(cut_bits))
        model.addConstr(temp_degree <= blue_vars_count - delta_total_b - gp.quicksum(cut_bits))
        model.addConstr(temp_degree <= total_equations)

        # Set objective function
        model.setObjective(temp_degree-0.01*sum_const_cond, GRB.MAXIMIZE)
        print("Constraints and objective function set")

        # Solve model
        print("Starting model solution...")
        model.optimize()

        # Output results
        if model.SolCount == 0:
            continue

        # Output detailed results to file
        f = open(f"../red_result/SHA3_512_round_{num_rounds + 1}_preimage_key={key}_32.py", 'w')

        # Output statistical results
        f.write(f"Red_variables={red_vars_count.getValue() - delta_total_r.getValue()}\n")
        f.write(f"Blue_variables={blue_vars_count.getValue() - delta_total_b.getValue()}\n")
        f.write(f"sum_const_cond = {sum_const_cond.getValue()}\n")
        f.write(f"temp_degree={temp_degree.x}\n")

        print("Keccak MILP automation modeling completed")

        # Output state information for LaTeX documentation
        row_num = 0
        temp = write_row(initial_state, row_num, '$A$')
        f.write(f"initial_state_output = {temp}\n")
        intermediate_states_output = []

        index = 1
        for round_state in intermediate_states:
            round_state_output = dict()
            theta_vars = round_state['theta_var']
            chi_vars = round_state['chi_var']

            row_num += 1
            C = round_state['C']
            temp = write_row_C(C, row_num, theta_vars, f'$C_{index}$')
            round_state_output['C'] = temp

            row_num += 0.4
            D = round_state['D']
            temp = write_row_D(D, row_num, theta_vars, f'$D_{index}$')
            round_state_output['D'] = temp

            row_num += 0.4
            theta = round_state['theta']
            temp = write_row_theta(theta, row_num, theta_vars, f'$\\theta_{index}$')
            round_state_output['theta'] = temp

            row_num += 1
            rho_state = round_state['rho_west']
            temp = write_row(rho_state, row_num, f'$\\rho_{index}$')
            round_state_output['rho_west'] = temp

            row_num += 1
            pi_state = round_state['chi']
            temp = write_row(pi_state, row_num, f'$\\pi_{index}$')
            round_state_output['chi'] = temp

            row_num += 1
            chi = round_state['rho_east']
            temp = write_row_chi(chi, row_num, chi_vars, f'$\\chi_{index}$')
            round_state_output['rho_east'] = temp

            index += 1
            intermediate_states_output.append(round_state_output)

        f.write(f"intermediate_states_output={intermediate_states_output}")
        f.close()