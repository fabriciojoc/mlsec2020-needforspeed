import sys
from nfs_wrapper import NFSWrapper

# initialize classifier with
# pre-trained model
clf = NFSWrapper(open("nfs.pickle", "rb"))
# open test file
test_file = open(sys.argv[1],'rb')
# get its bytes
bytez = test_file.read()
# predict pe file
pred, prob = clf.predict(bytez)
# print probabilities
print("Prediction: ", pred)
print("Probability: ", prob)
