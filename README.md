# RealCErrorMessaging

Install libdwarf

```bash
cd ~/src
git clone https://github.com/davea42/libdwarf-code.git
mkdir -p ~/build/libdwarf
cd ~/build/libdwarf
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="$HOME/local" ~/src/libdwarf-code
make
make install
```

### Install libdwarf

You need to install libdwarf before building this project.

1. Go to your source directory:

```bash
cd ~/src
```

2. Clone libdwarf:

```bash
git clone https://github.com/davea42/libdwarf-code.git
```

3. Go to your build directory:

```bash
cd ~/build/libdwarf
```

4. Configure the build:

```bash
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="$HOME/local" ~/src/libdwarf-code
```

```bash
cmake -G "Unix Makefiles" \
-DCMAKE_INSTALL_PREFIX="$HOME/local" \
-DBUILD_SHARED=YES \
-DBUILD_NON_SHARED=NO \
~/src/libdwarf-code
```

5. Build and install:

```bash
make
make install
```




## Running the program
Running realerrors is very simple as intended. Ensure that you have compiled your original source file using the '-g' flag (as you often would anyways). To attach our program, simply run ./realerrors ./{program-to-debug}. Now, upon a segmentation fault, you should get more useful info!

Ex:

```bash
make
gcc -g -o lkbug linuxKernelBug.c
./realerrors ./lkbug
```

The above example (we have included the bug in our files for the project), should produce the following output:


```bash
Stack Trace:
linuxKernelBug.c:63		main
linuxKernelBug.c:47		tun_chr_poll
Null Pointer Dereference Error
User Program exited with status 1
```


## Testing
To run our primary test suite for the program, which tests different types of segfaults, simply run the following:

```bash
make
./realerrors ./testSuite {type} 0
```

Our estimates of the overhead based on our hardware is:

```bash
make
./overhead
```


| Run Type | Volume  | avg with (ms) | avg without (ms) | overhead (ms) | Slowdown % |
| -------- | ------- | ------------- | ---------------- | ------------- | ---------- |
| deref    | 1000    | 27.02         | 5.00             | 22.03         | 440.80     |
| deref    | 10000   | 27.74         | 5.79             | 21.95         | 379.29     |
| deref    | 100000  | 28.92         | 4.87             | 24.05         | 493.77     |
| deref    | 1000000 | 36.86         | 10.78            | 26.07         | 241.85     |
| rec      | 1000    | 23.77         | 11.43            | 12.34         | 107.91     |
| rec      | 10000   | 23.20         | 11.22            | 11.97         | 106.70     |
| rec      | 100000  | 26.92         | 12.33            | 14.60         | 118.45     |
| rec      | 1000000 | 34.60         | 14.20            | 20.40         | 143.68     |
| bus      | 1000    | 28.48         | 5.70             | 22.78         | 399.40     |
| bus      | 10000   | 29.00         | 6.01             | 23.00         | 382.92     |
| bus      | 100000  | 33.73         | 7.98             | 25.75         | 322.54     |
| bus      | 1000000 | 40.53         | 14.59            | 25.95         | 177.88     |
| 2free    | 1000    | 16.36         | 7.92             | 8.44          | 106.58     |
| 2free    | 10000   | 15.53         | 6.22             | 9.31          | 149.62     |
| 2free    | 100000  | 19.98         | 7.82             | 12.17         | 155.64     |
| 2free    | 1000000 | 38.44         | 16.53            | 21.91         | 132.57     |
| bounds   | 1000    | 17.39         | 8.51             | 8.88          | 104.31     |
| bounds   | 10000   | 17.99         | 9.07             | 8.92          | 98.42      |
| bounds   | 100000  | 20.82         | 8.69             | 12.13         | 139.60     |
| bounds   | 1000000 | 44.06         | 24.20            | 19.85         | 82.03      |
| wonprot  | 1000    | 26.78         | 4.33             | 22.45         | 519.00     |
| wonprot  | 10000   | 25.89         | 3.13             | 22.76         | 727.94     |
| wonprot  | 100000  | 28.34         | 4.96             | 23.38         | 471.74     |
| wonprot  | 1000000 | 35.17         | 10.81            | 24.36         | 225.26     |
| control  | 1000    | 16.73         | 9.54             | 7.18          | 75.27      |
| control  | 10000   | 17.44         | 10.19            | 7.26          | 71.26      |
| control  | 100000  | 19.26         | 9.12             | 10.15         | 111.26     |
| control  | 1000000 | 38.94         | 18.85            | 20.08         | 106.53     |
