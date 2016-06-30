#!/usr/bin/env python3

###################################################################
#                                                                 #
#   ARM-based instruction scheduler and register allocator        #
#                                                                 #
#   Input: C-like-code in SSA form with ^ and & (see examples).   #
#   Output: commented assembly (eor/and/ldr/str).                 #
#                                                                 #
#   Disclaimer: hacky on purpose, read carefully.                 #
#   Pipelining and alignment need to be done manually.            #
#                                                                 #
#                                       By Anonymous - May 2016   #
#                                                                 #
###################################################################

import sys
#import operator

def push_up_rhs(sbox, sbox_text):
  #try to reduce the active data set by immediately using variables
  numswaps = 0
  for i in range(len(sbox)):
    var = sbox[i][0]
    for j in range(i+2,len(sbox)):
      if var in sbox[j][1]:
        k = j
        #try to move up by swapping with sbox[k-1] if useful and no dependencies
        while k > i+1 and var not in sbox[k-1][1] and sbox[k][0] not in sbox[k-1][1] and sbox[k-1][0] not in sbox[k][1]:
          #print('Swapping var',var,':',sbox[k-1],k-1,'with',sbox[k],k)
          swap(sbox, sbox_text, k-1, k)
          numswaps += 1
          k -= 1
  return numswaps

def push_down_lhs(sbox, sbox_text):
  #try to reduce the active data set by initializing variables as late as possible
  numswaps = 0
  for i in range(len(sbox)-1):
    #if variable will actually still occur on the RHS
    if sbox[i][0] in [rhs for pair in sbox[i+1:] for rhs in pair[1]]:
      j = i
      #try to move down by swapping with sbox[j+1] if useful and no dependencies
      while j < len(sbox)-1 and sbox[j][0] not in sbox[j+1][1] and sbox[j+1][0] not in sbox[j][1]:
        #print('Swapping',':',sbox[1],'with',sbox[j+1])
        swap(sbox, sbox_text, j, j+1)
        numswaps += 1
        j += 1
  return numswaps

def priorityschedule(sbox, sbox_text, priorities):
  #priority-based selection sort with boundaries
  numswaps = 0
  for i in range(len(sbox)-1):
    var = sbox[i][0]
    maxpriority = priorities[var]
    maxj = i
    j = i+1
    while j < len(sbox) and var not in sbox[j][1] and sbox[j][0] not in sbox[i][1]:
      if priorities[sbox[j][0]] > maxpriority:
        maxpriority = priorities[sbox[j][0]]
        maxj = j
      j += 1
    if maxj != i:
      #print('Swapping',':',sbox[1],'with',sbox[j+1])
      swap(sbox, sbox_text, i, maxj)
      numswaps += 1
  return numswaps

def swap(sbox, sbox_text, i, j):
  sbox[i], sbox[j] = sbox[j], sbox[i]
  sbox_text[i], sbox_text[j] = sbox_text[j], sbox_text[i]

def lifetimes(sbox):
  #compute the lifetimes, measured in number of instructions, that variables are active
  lifetimes = {}
  for i in range(len(sbox)):
    var = sbox[i][0]
    for j in range(len(sbox)-1,i,-1):
      if var in sbox[j][1]:
        lifetimes[var] = j-i
        break
  #print(sorted(lifetimes.items(), key=operator.itemgetter(1)))
  #print('with has avg', sum([lifetimes[x] for x in lifetimes])/len(lifetimes))
  return lifetimes

def priorities(sbox):
  #compute priorities (idea based on schedule131.py)
  variables = {}
  priorities = {}
  for i in reversed(sbox):
    prior = 0
    var = i[0]
    if var in variables:
      variables[var] += 1
      add = variables[var]
    else:
      variables[var] = 1
      add = 1
    for v in i[1]:
      if v in variables:
        variables[v] += add
      else:
        variables[v] = add
    priorities[var] = variables[var]
  #print(sorted(priorities.items(), key=operator.itemgetter(1)))
  #print('with has avg', sum([priorities[x] for x in priorities])/len(priorities))
  return priorities

def regfree(registers):
  for r in registers:
    if registers[r] == "X":
      return r
  return None

def regtoclear(sboxslice, registers):
  #aka vartospill
  #if no longer necessary as input, choose that
  #otherwise, choose for reg with longest distance until need
  maxdist = -1
  maxr = "X"
  #(don't?) ban output registers
  #suitableregisters = registers
  #suitableregisters = {r: v for r,v in registers.items() if not (v.lower().startswith('s') and v.endswith('m'))}
  suitableregisters = {r: v for r,v in registers.items() if not v.lower().startswith('s')}

  for r in suitableregisters:
    necessary = False
    for j in range(1,len(sboxslice)):
      if sboxslice[j][0] == registers[r]:
        break
      if registers[r] in sboxslice[j][1]:
        necessary = True
        if j > maxdist:
          maxdist = j
          maxr = r
        break
    if registers[r].lower().startswith('s'):
      return (r, True)
    if not necessary:
      return (r, False)
  assert maxr != "X"
  return (maxr, True)

def stacktoclear(sboxslice, stack):
  for i in range(len(stack)):
    necessary = False
    if stack[i] == None or stack[i].lower().startswith('s'):
      continue
    else:
      for j in range(len(sboxslice)):
        if stack[i] in sboxslice[j][1]:
          necessary = True
          break
    if not necessary:
      return (i, False)
  return (len(stack), True)

def recomputepossible(sbox, registers, i, v):
  for j in range(i-1,-1,-1):
    if sbox[j][0] == v:
      return all(x in registers.values() for x in sbox[j][1])
  return False

def storeonstack(sboxslice, stack, spstart, r, v, output):
  #store on stack, make it possible to reuse stack space
  if v in stack:
    return False
  s, append = stacktoclear(sboxslice, stack)
  if append:
    stack.append(v)
  else:
    stack[s] = v
  output.append('str {:>3s}, [sp, #{:<4d}] //Store {:s}/{:s} on stack'.format(r, (spstart-1-s)*4, r, v))
  return True

def allocate(sbox, sbox_text, registers, stack):
  output = []
  spstart = len(stack)
  numloads = 0
  numstores = 0
  numrands = 0 #set to n*32 for nth round

  for i in range(len(sbox)):
    for v in sbox[i][1]:
      #make sure that inputs are in registers, might have to clear one
      if v not in registers.values() and v != 'rand()' and v != '2':
        r = regfree(registers)
        if r == None:
          #dont clear another required register
          r, necessary = regtoclear(sbox[i:], {r: v for r,v in registers.items() if v not in sbox[i][1]})
          if necessary and storeonstack(sbox[i:], stack, spstart, r, registers[r], output):
            numstores += 1
        output.append('ldr {:>3s}, [sp, #{:<4d}] //Load {:s} into {:s}'.format(r, (spstart-1-stack.index(v))*4, v, r))
        numloads += 1
        #but wait a minute, perhaps I could have recomputed it
        if recomputepossible(sbox, registers, i, v):
          output.append('Wait, I could have recomputed that!')
        registers[r] = v
    #now all inputs are in registers, what about the output?
    var = sbox[i][0]
    r = regfree(registers)
    if r == None:
      r, necessary = regtoclear(sbox[i:], registers)
      if necessary and storeonstack(sbox[i:], stack, spstart, r, registers[r], output):
        numstores += 1
    instr = 'eor' if '^' in sbox_text[i] else 'and' if '&' in sbox_text[i] else 'ldr'
    if instr == 'ldr':
      output.append('{:s} {:>3s}, [sp, #{:<4d}] //Exec {:s} into {:s}'.format(instr, r, (spstart-1-8-numrands)*4, sbox_text[i].strip(), r))
      numrands += 1
    else:
      rinput1 = [r for r in registers if registers[r] == sbox[i][1][0]][0]
      rinput2 = [r for r in registers if registers[r] == sbox[i][1][1]][0]
      output.append('{:s} {:>3s}, {:>3s}, {:>3s}    //Exec {:s} into {:s}'.format(instr, r, rinput1, rinput2, sbox_text[i].strip(), r))
    registers[r] = var
    #output.append(str(registers))
  output.append('//' + str(sorted(registers.items(), key=lambda x: int(x[0][1:]))))
  print('Result: {:d} loads and {:d} stores'.format(numloads,numstores), file=sys.stderr)
  return output


if __name__ == "__main__":

  filename = 'sbox.txt'

  if len(sys.argv) < 2:
    print('No argument given, defaulting to', filename, file=sys.stderr)
  else:
    filename = sys.argv[1]

  #read sbox_text als a list of tuples
  #assumes uniqueness of variables names, e.g., SSA
  #assumes only ^ and &, xnors are interpreted as xors, rest is interpreted as ldr of randomness
  sbox = []
  with open(filename, 'r') as sbox_file:
    sbox_text = sbox_file.readlines()
  for line in sbox_text:
    if line.strip():
      linelist = line.strip(';\n ').split()
      sbox.append((linelist[0], [linelist[2], linelist[4]]))

  #schedule instructions to reduce lifetime of variables
  #manually try multiple combinations and orders here

  #print(push_up_rhs(sbox, sbox_text), 'swaps occured', file=sys.stderr)
  #print(push_down_lhs(sbox, sbox_text), 'swaps occured', file=sys.stderr)
  print(push_up_rhs(sbox, sbox_text), 'swaps occured', file=sys.stderr)
  #print(priorityschedule(sbox, sbox_text, priorities(sbox)), 'swaps occured', file=sys.stderr)

  #print(lifetimes(sbox))
  #print(priorities(sbox))

  #starting situation unmasked
  registers = {'r0':'X','r1':'X','r2':'X','r3':'X','r4':'U0','r5':'U1','r6':'U2','r7':'U3','r8':'U4','r9':'U5','r10':'U6','r11':'U7','r12':'X','r14':'X'}
  stack = []

  #starting situation masked
  #registers = {'r0':'X','r1':'X','r2':'X','r3':'X','r4':'x0m','r5':'x1m','r6':'x2m','r7':'x3m','r8':'x4m','r9':'x5m','r10':'x6m','r11':'x7m','r12':'X','r14':'X'}
  #stack = ['x'+str(i) for i in range(8)] + [None]*321 #relevant part of the stack at the start

  print('\n'.join(allocate(sbox, sbox_text, registers, stack)))

  #prettyprint
  #for line in sbox_text:
  #  print(line)
