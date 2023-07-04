import os

root_path = "/path/to/AFL"

white_dict = {'c':'c', 'cc':'c++', 'cpp':'c++', 'h':'c', 'py':'python', 'sh':'shell', 'json':'json', 'llvm':'llvm', 'diff':'diff', 'patch':'diff'}
black_list = ['png', 'jpg', 'jpeg', 'mp4', 'bmp', 'gif', 'ico', 'jp2', 'jxr', 'tiff', 'webp', 'txt','exe', 'so', 'o', 'md']

n = 1

def merge(n, path):
    dir_list = os.listdir(path)
    print (dir_list)
    t = 0
    for dir in dir_list:
        if os.path.isdir(dir):
            t = 1
    if t == 1:
        with open(target_md, "a", encoding='utf-8') as file:
                    file.writelines("#" * n + " " + "." + "\n")
        file.close()
    for dir in dir_list:
        contents = []
        suffix = dir.split('.')[-1]
        print("suffix: {}".format(suffix))
        dir_file = path + '\\' + dir
        
        if os.path.isfile(dir_file):
            if suffix in black_list or ("README" in dir) or ("LICENSE" in dir):
                continue
            elif suffix in white_dict:
                with open(dir_file, 'r', encoding='utf-8') as file:
                    contents.append("#" * (n + t) + " " + dir + "\n")
                    contents.append("```" + white_dict[suffix] + "\n" + file.read() + "\n" + "```" + "\n")
                    print(dir)
                with open(target_md, "a", encoding='utf-8') as file:
                    file.writelines(contents)
                file.close()
            elif "Makefile" in dir:
                with open(dir_file, 'r', encoding='utf-8') as file:
                    contents.append("#" * (n + t) + " " + dir + "\n")
                    contents.append("```" + "makefile" + "\n" + file.read() + "\n" + "```" + "\n")
                    print(dir)
                with open(target_md, "a", encoding='utf-8') as file:
                    file.writelines(contents)
                file.close()
            else:
                with open(dir_file, 'r', encoding='utf-8') as file:
                    contents.append("#" * (n + t) + " " + dir + "\n")
                    contents.append("```" + "shell" + "\n" + file.read() + "\n" + "```" + "\n")
                    print(dir)
                with open(target_md, "a", encoding='utf-8') as file:
                    file.writelines(contents)
                file.close() 

        elif os.path.isdir(dir_file) and dir != ".git":
            with open(target_md, "a", encoding='utf-8') as file:
                file.writelines("#" * n + " " + "> " + suffix + "\n")
            file.close()
            next_file = dir_file + '\\'
            merge(n + 1, next_file)
    return

target_md = "/path/to/md" + root_path.split('\\')[-1] + ".md"
with open(target_md, "a", encoding='utf-8') as file:
    file.writelines("#" * n + " " + (root_path.split('\\')[-1]) + "\n")
    file.writelines("[TOC]" + "\n")
    file.close()
merge(n + 1, root_path)
print("[+] All Done")