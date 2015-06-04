class pTest{
private:

public:
	pTest();
	~pTest();

	void printModulesA(Process * A);
	void printModulesB(Process * A);
	void printHandles(Process * A);
	void printThreads(Process * A);
	void printSystemModules(Process * A);

	void Tmain();
};